"""
Security IR API wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the Jira API for use in the Security Incident Response integration.
"""

import os
import logging
from typing import List, Dict, Optional, Any, Union

import boto3
from boto3 import client, resource

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Import mappers with fallbacks for different environments
try:
    from jira_sir_mapper import map_watchers
except ImportError:
    try:
        from assets.mappers.python.jira_sir_mapper import map_watchers
    except ImportError:
        from ...mappers.python.jira_sir_mapper import map_watchers

class SecurityIRClient:
    """Class to handle Security IR API interactions"""

    def __init__(self):
        """Initialize the Jira client"""
        self.client = self._create_client()

    def _create_client(self) -> client:
        """
        Create a Jira client instance
        
        Returns:
            Security IR client or None if creation fails
        """
        try:
            return client("security-ir")
            
        except Exception as e:
            logger.error(f"Error creating Security IR client: {str(e)}")
            return None
        
    def get_case(self, case_id: str) -> dict:
        """
        Get a Security IR case by ID
        
        Args:
            case_id: The Security IR case ID
            
        Returns:
            Security IR case object or None if retrieval fails
        """
        try:
            return self.client.get_case(case_id)
        except Exception as e:
            logger.error(f"Error getting case %s from Security IR API: {str(e)}", case_id)
            return None
        
    def create_case(self, fields: Dict[str, Any]) -> Optional[Any]:
        """
        Create a new Security IR case
        
        Args:
            fields: Dictionary of issue fields
            
        Returns:
            Created Security IR case or None if creation fails
        """
        try:
            return self.client.create_issue(fields=fields)
        except Exception as e:
            logging.error("Error creating Security IR case: %s", str(e))

            return None
        
    def update_case(self, case_id: str, fields: Dict[str, Any]) -> bool:
        """
        Update a Security IR case
        
        Args:
            issue_id: The Security IR case ID
            fields: Dictionary of issue fields to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            case = self.client.issue(case_id)
            case.update(fields=fields)
            return True
        except Exception as e:
            logger.error(f"Error updating Security IR case %s: {str(e)}", case_id)
            return False
        
    def update_status(self, case_id: str, status: str, comment: Optional[str] = None) -> bool:
        """
        Update the status of a Security IR case
        
        Args:
            case_id: The Security IR case ID
            status: Target status to set case to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get current issue to check status
            case = self.client.issue(case_id)
            current_status = case.fields.status.name

            # Only attempt transition if status is different
            if current_status != status:
                # Get available transitions
                case.update_case_status(case_id, status)
                
            else:
                logger.error(f"Could not change case status to {status}")
                return False
                    
            return True
        except Exception as e:
            logger.error(f"Error updating status for Jira issue %s: {str(e)}", case_id)
            return False
        
    