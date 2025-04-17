#!/usr/bin/env python3

"""

Data Storage Module for CryptoMining Detection System



This module handles:

1. Saving and loading mining reference data

2. Managing stored data

"""



import os

import json

import pickle

import logging

from typing import List, Dict, Any, Optional

from datetime import datetime



# Configure logging

logging.basicConfig(level=logging.INFO, 

                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logger = logging.getLogger('data_storage')



class DataStorage:

    """

    Class for storing and retrieving data for the crypto mining detection system.

    """

    

    def __init__(self, data_dir: str = None):

        """

        Initialize the data storage.

        

        Args:

            data_dir: Directory to store data (default: ./data)

        """

        # Set data directory

        if data_dir is None:

            script_dir = os.path.dirname(os.path.abspath(__file__))

            self.data_dir = os.path.join(script_dir, 'data')

        else:

            self.data_dir = data_dir

            

        # Create data directory if it doesn't exist

        if not os.path.exists(self.data_dir):

            os.makedirs(self.data_dir)

            logger.info(f"Created data directory: {self.data_dir}")

        

        # Set reference data path

        self.mining_ref_path = os.path.join(self.data_dir, 'mining_reference.pkl')

        self.mining_ref_meta_path = os.path.join(self.data_dir, 'mining_reference_meta.json')

    

    def save_mining_reference(self, intervals: List[float]) -> bool:

        """

        Save mining intervals as reference data.

        

        Args:

            intervals: List of time intervals from mining traffic

            

        Returns:

            True if saved successfully, False otherwise

        """

        try:

            # Save the data as pickle

            with open(self.mining_ref_path, 'wb') as f:

                pickle.dump(intervals, f)

            

            # Save metadata as JSON

            metadata = {

                'timestamp': datetime.now().isoformat(),

                'count': len(intervals),

                'min': min(intervals) if intervals else 0,

                'max': max(intervals) if intervals else 0,

                'mean': sum(intervals) / len(intervals) if intervals else 0

            }

            

            with open(self.mining_ref_meta_path, 'w') as f:

                json.dump(metadata, f, indent=2)

            

            logger.info(f"Saved {len(intervals)} mining intervals as reference data")

            return True

            

        except Exception as e:

            logger.error(f"Error saving mining reference data: {str(e)}")

            return False

    

    def load_mining_reference(self) -> Optional[List[float]]:

        """

        Load mining reference data.

        

        Returns:

            List of mining intervals or None if not found

        """

        if not os.path.exists(self.mining_ref_path):

            logger.warning("Mining reference data not found")

            return None

            

        try:

            with open(self.mining_ref_path, 'rb') as f:

                intervals = pickle.load(f)

            

            logger.info(f"Loaded {len(intervals)} mining intervals from reference data")

            return intervals

            

        except Exception as e:

            logger.error(f"Error loading mining reference data: {str(e)}")

            return None

    

    def get_mining_reference_metadata(self) -> Optional[Dict[str, Any]]:

        """

        Get metadata about the mining reference data.

        

        Returns:

            Dictionary with metadata or None if not found

        """

        if not os.path.exists(self.mining_ref_meta_path):

            logger.warning("Mining reference metadata not found")

            return None

            

        try:

            with open(self.mining_ref_meta_path, 'r') as f:

                metadata = json.load(f)

            

            return metadata

            

        except Exception as e:

            logger.error(f"Error reading mining reference metadata: {str(e)}")

            return None

    

    def save_results(self, results: Dict[str, Any], filename: str = None) -> str:

        """

        Save detection results to file.

        

        Args:

            results: Results data to save

            filename: Filename to save to (default: auto-generated)

            

        Returns:

            Path to saved file or empty string if failed

        """

        if filename is None:

            # Generate filename based on timestamp

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            filename = f"detection_results_{timestamp}.json"

        

        file_path = os.path.join(self.data_dir, filename)

        

        try:

            with open(file_path, 'w') as f:

                json.dump(results, f, indent=2)

            

            logger.info(f"Saved results to {file_path}")

            return file_path

            

        except Exception as e:

            logger.error(f"Error saving results: {str(e)}")

            return ""

    

    def has_mining_reference(self) -> bool:

        """

        Check if mining reference data exists.

        

        Returns:

            True if reference data exists, False otherwise

        """

        return os.path.exists(self.mining_ref_path)



# Simple test if run directly

if __name__ == "__main__":

    # Test saving and loading reference data

    storage = DataStorage()

    

    # Check if reference data exists

    if storage.has_mining_reference():

        print("Mining reference data exists.")

        metadata = storage.get_mining_reference_metadata()

        if metadata:

            print(f"Metadata: {metadata}")

    else:

        print("No mining reference data found.")

        

        # Create sample reference data

        sample_intervals = [0.001, 0.002, 0.001, 0.003, 0.002, 0.001, 0.002, 0.003]

        storage.save_mining_reference(sample_intervals)

        print("Created sample mining reference data.") 