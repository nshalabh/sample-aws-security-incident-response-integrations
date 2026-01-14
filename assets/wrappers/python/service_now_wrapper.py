"""
ServiceNow API wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the ServiceNow API for use in the Security Incident Response integration.
"""

import logging
import boto3
from typing import Dict, Optional, Any, List
from pysnc import ServiceNowClient as SnowClient, GlideRecord
import jwt
import mimetypes
import requests
import time
import uuid
from requests.auth import AuthBase
import gc

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ssm_client = boto3.client("ssm")

# Static variables
CONTENT_TYPE = 'application/x-www-form-urlencoded; charset=UTF-8'
JWT_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
# JWT_HEADER = {
#             'alg': 'RS256',  # Or RS256 if using certificate-based signing
#             'typ': 'JWT'
#             # 'kid': 'key_id_if_applicable' # If you have a specific key ID
#         }
ATTACHMENT_CONTENT_TYPE = 'application/octet-stream'

class ServiceNowJWTAuth(AuthBase):
    """ServiceNow JWT authentication handler."""
    def __init__(self, instance_id, client_id, client_secret, jwt):
        """Initialize ServiceNow JWT authentication.

        Args:
            instance_id (str): ServiceNow instance ID
            client_id (str): OAuth client ID
            client_secret (str): OAuth client secret
            jwt (str): Signed JWT token from OIDC provider
        """
        self.instance_id = instance_id
        self.client_id = client_id
        self.__secret = client_secret
        self.__jwt = jwt
        self.__token = None
        self.__expires_at = None

    def _get_access_token(self, request):
        """Get OAuth access token using JWT assertion.

        Args:
            request: HTTP request object

        Returns:
            tuple: Tuple containing (access_token, expires_at)
        """
        token_url = f"https://{self.instance_id}.service-now.com/oauth_token.do"
        headers = {
            'Content-Type': CONTENT_TYPE,
            'Authentication': f"Bearer {self.__jwt}"
        }
        data = {
            'grant_type': JWT_GRANT_TYPE,
            'assertion': self.__jwt,
            'client_id': self.client_id,
            'client_secret': self.__secret
        }
        r = requests.post(token_url, headers=headers, data=data)
        if r.status_code != 200:
            raise Exception("Failed to perform auth, see System Logs in ServiceNow")
        data = r.json()
        expires = int(time.time()+data['expires_in'])
        return data['access_token'], expires

    def __call__(self, request):
        """Add authorization header to request.

        Args:
            request: HTTP request object to authorize

        Returns:
            request: Modified request with authorization header
        """
        if not self.__token or time.time() > self.__expires_at:
            logger.info("Getting access token")
            self.__token, self.__expires_at = self._get_access_token(request)
        request.headers['Authorization'] = f"Bearer {self.__token}"
        return request


# TODO: Consider refactoring the micro-service implementation in the solution to use the Singleton or Factory method design pattern. See https://refactoring.guru/design-patterns/python
class ServiceNowClient:
    """Class to handle ServiceNow API interactions."""

    def __init__(self, instance_id, jwt_header, **kwargs):
        """
        Initialize the ServiceNow client with OAuth2 authentication.

        Args:
            instance_id (str): ServiceNow instance ID
            **kwargs: OAuth configuration parameters
        """
        if not instance_id:
            raise ValueError("No valid authentication method provided")
            
        self.instance_id = instance_id
        self.jwt_header = jwt_header
        self.client_id_param_name = kwargs.get('client_id_param_name')
        self.client_secret_param_name = kwargs.get('client_secret_param_name')
        self.user_id_param_name = kwargs.get('user_id_param_name')
        self.private_key_asset_bucket_param_name = kwargs.get('private_key_asset_bucket_param_name')
        self.private_key_asset_key_param_name = kwargs.get('private_key_asset_key_param_name')
        
        # Validate required parameters are provided
        required_params = [
            self.client_id_param_name,
            self.client_secret_param_name, 
            self.user_id_param_name,
            self.private_key_asset_bucket_param_name,
            self.private_key_asset_key_param_name
        ]
        
        if not all(required_params):
            raise ValueError("No valid authentication method provided")
        
        self._s3_resource = None  # Lazy loading
        self._client = None  # Lazy loading

    def __get_parameter(self, param_name: str) -> Optional[str]:
        """Fetch a parameter from SSM Parameter Store.

        Args:
            param_name (str): Parameter name
            
        Returns:
            Optional[str]: Parameter value or None if retrieval fails
        """
        try:
            if not param_name:
                logger.error("No parameter name provided")
                return None

            response = ssm_client.get_parameter(
                Name=param_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(f"Error retrieving parameter {param_name} from SSM: {str(e)}")
            return None

    def __get_encoded_jwt(self, client_id: str, user_id: str) -> Optional[str]:
        """Generate encoded JWT using private key from S3 asset.

        Args:
            client_id (str): OAuth client ID for JWT issuer
            user_id (str): ServiceNow user ID for JWT subject

        Returns:
            Optional[str]: Encoded JWT or None if generation fails
        """
        try:
            bucket = self.__get_parameter(self.private_key_asset_bucket_param_name)
            key = self.__get_parameter(self.private_key_asset_key_param_name)
            
            if not bucket or not key or not user_id or not client_id:
                logger.error("Missing required parameters for JWT generation")
                return None
            
            # Read private key with minimal memory footprint
            if not self._s3_resource:
                self._s3_resource = boto3.resource('s3')
            
            response = self._s3_resource.Object(bucket, key).get()
            private_key = response['Body'].read().decode('utf-8')
            response['Body'].close()
            del response  # Explicit cleanup
            
            # Create minimal JWT payload
            payload = {
                "iss": client_id,
                "sub": user_id,
                "aud": client_id,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "jti": str(uuid.uuid4())
            }
            
            # Encode JWT
            encoded_jwt = jwt.encode(payload, private_key, algorithm=self.jwt_header["alg"], headers=self.jwt_header)
            
            # Clear sensitive data and force garbage collection
            del private_key, payload
            gc.collect()
            
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Error generating JWT: {str(e)}")
            return None
        
    def __get_jwt_oauth_access_token(self: Any) -> Optional[str]:
        """Get OAuth access token using JWT authentication.

        Returns:
            Optional[str]: OAuth access token or None if retrieval fails
        """
        try:
            if not self.instance_id:
                logger.error("No ServiceNow instance id provided")
                return None
            
            # Get parameters for JWT OAuth
            client_secret = self.__get_parameter(self.client_secret_param_name)
            client_id = self.__get_parameter(self.client_id_param_name)
            user_id = self.__get_parameter(self.user_id_param_name)
            
            # Get encoded JWT
            encoded_jwt = self.__get_encoded_jwt(client_id, user_id)

            # Prepare request headers, data to get OAuth access token using encoded_jwt
            token_url = f"https://{self.instance_id}.service-now.com/oauth_token.do"
            headers = {
                        'Content-Type': CONTENT_TYPE,
                        'Authentication': f"Bearer {encoded_jwt}"
                    }
            data = {
                'grant_type': JWT_GRANT_TYPE,
                'assertion': encoded_jwt,
                'client_id': client_id,
                'client_secret': client_secret
            }
            response = requests.post(token_url, headers=headers, data=data)
            return (response.json())['access_token']
        except requests.exceptions.RequestException as e:
            logger.error("HTTP request failed during OAuth token retrieval")
            return None
        except (KeyError, ValueError) as e:
            logger.error("Invalid response format from OAuth endpoint")
            return None
        
    def __get_client(self) -> Optional[SnowClient]:
        """Get ServiceNow client with lazy loading."""
        if self._client is None:
            self._client = self.__create_client()
        return self._client
    
    def __create_client(self) -> Optional[SnowClient]:
        """Create a ServiceNow client instance with OAuth2 authentication.

        Returns:
            Optional[SnowClient]: PySNC ServiceNow client or None if creation fails
        """
        try:
            if not self.instance_id:
                logger.error("No ServiceNow instance id provided")
                return None
            
            instance_url = f"https://{self.instance_id}.service-now.com"

            # Get OAuth2 parameters
            client_id = self.__get_parameter(self.client_id_param_name)
            client_secret = self.__get_parameter(self.client_secret_param_name)
            user_id = self.__get_parameter(self.user_id_param_name)
            
            if not all([client_id, client_secret, user_id]):
                logger.error("Missing OAuth2 credentials")
                return None
            
            # Generate JWT token
            encoded_jwt = self.__get_encoded_jwt(client_id, user_id)
            
            if not encoded_jwt:
                logger.error("Failed to generate JWT token")
                return None
            
            # Create ServiceNow client
            auth = ServiceNowJWTAuth(self.instance_id, client_id, client_secret, encoded_jwt)
            return SnowClient(instance_url, auth)

        except Exception as e:
            logger.error(f"Error creating ServiceNow client: {str(e)}")
            return None

    def __get_glide_record(self, record_type: str) -> Optional[GlideRecord]:
        """Prepare a Glide Record using ServiceNowClient for querying.

        Args:
            record_type (str): Type of ServiceNow record (e.g., 'incident')

        Returns:
            Optional[GlideRecord]: GlideRecord instance or None if retrieval fails
        """
        try:
            client = self.__get_client()
            if not client:
                return None
            return client.GlideRecord(record_type)
        except Exception as e:
            logger.error(f"Error preparing GlideRecord: {str(e)}")
            return None

    def __prepare_service_now_incident(
        self, glide_record: GlideRecord, integration_module: str, fields: Dict[str, Any]
    ) -> GlideRecord:
        """Prepare ServiceNow Glide Record for incident creation.

        Args:
            glide_record (GlideRecord): ServiceNow Glide Record
            integration_module (str): Integration module type ('itsm' or 'ir')
            fields (Dict[str, Any]): ServiceNow mapped fields

        Returns:
            GlideRecord: Glide record for Incident creation with added fields
        """
        # Validate that fields is a dictionary
        if not isinstance(fields, dict):
            logger.error(
                f"Fields parameter must be a dictionary, got {type(fields)}: {fields}"
            )
            return glide_record

        glide_record.short_description = fields.get("short_description", "")
        glide_record.description = fields.get("description", "")
        if "state" in fields:
            glide_record.state = fields["state"]
        if integration_module == "itsm":
            glide_record.impact = fields.get("impact", "2")
            glide_record.priority = fields.get("priority", "3")
            glide_record.urgency = fields.get("urgency", "2")
            glide_record.severity = fields.get("severity", "1")
        elif integration_module == "ir":
            glide_record.impact = fields.get("impact", "3")
            glide_record.priority = fields.get("priority", "4")
            glide_record.urgency = fields.get("urgency", "3")
        glide_record.comments_and_work_notes = fields.get("comments_and_work_notes", "")
        glide_record.comments = fields.get("comments", "")
        glide_record.category = fields.get("category", "inquiry")
        glide_record.subcategory = fields.get("subcategory", "internal application")
        # if "incident_state" in fields:
        #     glide_record.incident_state = fields["incident_state"]
        return glide_record

    def get_incident_with_display_values(
        self, incident_number: str, integration_module: str = "itsm"
    ) -> Optional[Dict[str, Any]]:
        """Get a ServiceNow incident by incident_number.

        Args:
            incident_number (str): The ServiceNow incident number
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[Dict[str, Any]]: Incident record dictionary or None if retrieval fails
        """
        try:
            # Force garbage collection before API call
            gc.collect()
            
            table_name = "incident" if integration_module == "itsm" else "sn_si_incident" if integration_module == "ir" else None
            if not table_name:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            if not glide_record:
                return None
                
            glide_record.add_query("number", incident_number)
            glide_record.query()
            
            if glide_record.next():
                # Serialize with memory management
                result = glide_record.serialize(display_value=True)
                del glide_record  # Clean up immediately
                gc.collect()
                return result
            else:
                del glide_record
                return None
                
        except Exception as e:
            logger.error(f"Error getting incident details for {incident_number} from ServiceNow: {str(e)}")
            gc.collect()
            return None

    def get_incident(
        self, incident_number: str, integration_module: str = "itsm"
    ) -> GlideRecord:
        """Get a ServiceNow incident by incident_number.

        Args:
            incident_number (str): The ServiceNow incident number
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[GlideRecord]: GlideRecord instance or None if retrieval fails
        """
        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                logger.info(
                    f"Incident details for {incident_number} from ServiceNow {table_name}: {glide_record}"
                )
                return glide_record
        except Exception as e:
            logger.error(
                f"Error getting incident details for {incident_number} from ServiceNow: {str(e)}"
            )
            return None

    def get_incident_attachments_details(
        self, service_now_incident_id: str, integration_module: str = "itsm"
    ) -> Optional[List[Dict[str, str]]]:
        """Get attachments for a ServiceNow incident.

        Args:
            service_now_incident_id (str): ServiceNow incident ID
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[List[Dict[str, str]]]: List of attachment details dictionaries or None if retrieval fails
        """
        try:
            # Force garbage collection before API call
            gc.collect()
            
            table_name = "incident" if integration_module == "itsm" else "sn_si_incident" if integration_module == "ir" else None
            if not table_name:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            if not glide_record:
                return None
                
            glide_record.add_query("number", service_now_incident_id)
            glide_record.query()
            
            if glide_record.next():
                attachments_list = []
                attachments = glide_record.get_attachments()
                
                # Process attachments with memory management
                for attachment in attachments:
                    attachment_details = {
                        "filename": attachment.file_name,
                        "content_type": attachment.content_type,
                    }
                    attachments_list.append(attachment_details)
                
                # Clean up immediately
                del glide_record, attachments
                gc.collect()
                return attachments_list
            else:
                del glide_record
                return None
                
        except Exception as e:
            logger.error(f"Error getting attachments for incident {service_now_incident_id} from ServiceNow: {str(e)}")
            gc.collect()
            return None

    def get_incident_attachment_data(
        self, glide_record: GlideRecord, attachment_name: str
    ) -> Optional[Dict[str, Any]]:
        """Get attachment data for a ServiceNow incident.

        Args:
            glide_record (GlideRecord): ServiceNow Glide Record
            attachment_name (str): Name of the attachment to retrieve

        Returns:
            Optional[Dict[str, Any]]: Dictionary containing attachment content, content type, and content size, or None if retrieval fails
        """
        try:
            attachments = glide_record.get_attachments()
            for attachment in attachments:
                if attachment.file_name == attachment_name:
                    # Temporary path to download the attachment
                    temp_path = f"/tmp/{attachment_name}"
                    attachment.write_to(temp_path)

                    # Read attachment content in binary mode
                    with open(temp_path, "rb") as f:
                        attachment_content = f.read()

                        # Return the complete temp path as attachment_url
                        attachment_content_type = attachment.content_type
                        attachment_content_length = attachment.size_bytes
                        attachment_data = {
                            "attachment_content": attachment_content,
                            "attachment_content_type": attachment_content_type,
                            "attachment_content_length": attachment_content_length,
                        }
                        return attachment_data
        except Exception as e:
            logger.error(
                f"Error getting attachment data for incident {glide_record.number} from ServiceNow: {str(e)}"
            )
            return None

    def create_incident(
        self, fields: Dict[str, Any], integration_module: str = "itsm"
    ) -> Optional[str]:
        """Create a new ServiceNow incident.

        Args:
            fields (Dict[str, Any]): Dictionary of incident fields
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[str]: Created ServiceNow incident number or None if creation fails
        """
        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.initialize()
            glide_record = self.__prepare_service_now_incident(
                glide_record, integration_module, fields
            )
            incident_sys_id = (
                glide_record.insert()
            )  # Insert the record and get the sys_id
            logger.info(
                f"Incident created with sys_id: {incident_sys_id} in {table_name}"
            )
            incident_number = glide_record.number
            logger.info(f"Newly created Incident Number: {incident_number}")
            return incident_number
        except Exception as e:
            logger.error(f"Incident creation failed with error: {e}")
            return None

    def update_incident(
        self,
        incident_number: str,
        fields: Dict[str, Any],
        integration_module: str = "itsm",
    ) -> Optional[GlideRecord]:
        """Update an existing ServiceNow incident.

        Args:
            incident_number (str): Incident number in ServiceNow to be updated
            fields (Dict[str, Any]): Dictionary of incident fields
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[GlideRecord]: Updated ServiceNow incident record or None if update fails
        """
        try:
            # Validate that fields is a dictionary
            if not isinstance(fields, dict):
                logger.error(
                    f"Fields parameter must be a dictionary, got {type(fields)}: {fields}"
                )
                return None

            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                glide_record = self.__prepare_service_now_incident(
                    glide_record, integration_module, fields
                )
                glide_record.update()
                logger.info(
                    f"Incident {incident_number} updated successfully in {table_name}"
                )
                return glide_record
            else:
                logger.error(f"Incident {incident_number} not found")
                return None
        except Exception as e:
            logger.error(f"Incident update failed with error: {e}")
            return None

    def add_incident_comment(
        self,
        incident_number: str,
        incident_comment: str,
        integration_module: str = "itsm",
    ) -> Optional[GlideRecord]:
        """Add a comment to an existing ServiceNow incident.

        Args:
            incident_number (str): Incident number in ServiceNow to be updated
            incident_comment (str): Comment to add to the incident
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[GlideRecord]: Updated ServiceNow incident record or None if update fails
        """
        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                glide_record.comments = incident_comment
                glide_record.update()
                logger.info(
                    f"Incident {incident_number} with comment {incident_comment} updated successfully in {table_name}"
                )
                return glide_record
            else:
                logger.error(f"Incident {incident_number} not found in {table_name}")
                return None
        except Exception as e:
            logger.error(f"Incident comment update failed with error: {e}")
            return None

    def upload_incident_attachment(
        self,
        incident_number: str,
        attachment_name: str,
        attachment_path: str,
        integration_module: str = "itsm",
    ) -> Optional[bool]:
        """Upload an attachment to a ServiceNow incident using REST API.

        Args:
            incident_number (str): The ServiceNow incident number
            attachment_name (str): Name of the attachment
            attachment_path (str): Path to the attachment file
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[bool]: True if upload successful, None if upload fails
        """

        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            # Get the incident record first
            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
            # Use REST API instead of AttachmentAPI GlideRecord to avoid 414 errors
                
                # Get OAuth access token
                oauth_access_token = self.__get_jwt_oauth_access_token()

                # Determine content type
                content_type = (
                    mimetypes.guess_type(attachment_name)[0]
                    or ATTACHMENT_CONTENT_TYPE
                )

                headers = {
                    "Authorization": f"Bearer {oauth_access_token}",
                    "Content-Type": content_type,
                }

                # Upload via REST API
                url = f"https://{self.instance_id}.service-now.com/api/now/attachment/file"
                params = {
                    "table_name": table_name,
                    "table_sys_id": glide_record.sys_id.get_display_value(),
                    "file_name": attachment_name,
                }

                with open(attachment_path, "rb") as f:
                    file_content = f.read()
                    response = requests.post(
                        url,
                        headers=headers,
                        params=params,
                        data=file_content,
                        timeout=30,
                    )

                if response.status_code == 201:
                    logger.info(
                        f"Uploaded attachment {attachment_name} to ServiceNow incident {incident_number} in {table_name}"
                    )
                    return True
                else:
                    logger.error(
                        f"Upload failed with status {response.status_code}: {response.text}"
                    )
                    return None
            else:
                logger.error(f"Incident {incident_number} not found in {table_name}")
                return None
        except Exception as e:
            logger.error(f"Attachment upload failed with error: {e}")
            return None

    def extract_incident_details(
        self,
        service_now_incident: Dict[str, Any],
        service_now_incident_attachments: Any,
    ) -> Dict[str, Any]:
        """Extract relevant details from a ServiceNow incident dictionary into a serializable dictionary.

        Args:
            service_now_incident (Dict[str, Any]): ServiceNow incident dictionary
            service_now_incident_attachments (Any): ServiceNow incident attachments

        Returns:
            Dict[str, Any]: Dictionary with serializable ServiceNow incident details
        """
        try:
            # Extract only essential fields to minimize memory usage
            incident_dict = {
                "sys_id": service_now_incident.get("sys_id"),
                "number": service_now_incident.get("number"),
                "short_description": service_now_incident.get("short_description"),
                "description": service_now_incident.get("description"),
                "state": service_now_incident.get("state"),
                "priority": service_now_incident.get("priority"),
                "urgency": service_now_incident.get("urgency"),
                "severity": service_now_incident.get("severity"),
                "sys_created_on": service_now_incident.get("sys_created_on"),
                "sys_created_by": service_now_incident.get("sys_created_by"),
                "attachments": service_now_incident_attachments or [],
            }
            
            # Clean up input parameters immediately
            del service_now_incident, service_now_incident_attachments
            gc.collect()
            
            return incident_dict
        except Exception as e:
            logger.error(f"Error extracting ServiceNow incident details: {str(e)}")
            gc.collect()
            return {
                "error": str(e),
                "number": service_now_incident.get("number") if service_now_incident else None
            }
