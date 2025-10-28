"""
Factory pattern for creating appropriate analyzer instances.
"""

from src.config import Config
from src.analyzers.malware_analyzer import MalwareAnalyzer
from src.analyzers.benignware_analyzer import BenignwareAnalyzer


def create_analyzer(config: Config):
    """
    Factory function to create the appropriate analyzer based on configuration.

    :param config: Configuration object with mode setting
    :return: Instance of MalwareAnalyzer or BenignwareAnalyzer
    :raises ValueError: If mode is not recognized
    """
    if config.mode == 'malware':
        return MalwareAnalyzer(config)
    elif config.mode == 'benignware':
        return BenignwareAnalyzer(config)
    else:
        raise ValueError(f"Unknown mode: {config.mode}. Must be 'malware' or 'benignware'")
