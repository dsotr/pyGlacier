# coding=utf-8

# Available glacier regions
REGIONS = {
    'us-east-1': 'US EAST (N. VIRGINIA)',
    'us-west-2': 'US WEST (OREGON)',
    'us-west-1': 'US WEST (N. CALIFORNIA)',
    'eu-west-1': 'EU (IRELAND)',
    'eu-central-1': 'EU (FRANKFURT)',
    'ap-southeast-2': 'ASIA PACIFIC (SYDNEY)',
    'ap-northeast-1': 'ASIA PACIFIC (TOKYO)',
}

# glacier API version
API_VERSION = '2012-06-01'
# Service name
SERVICE = 'glacier'
# Default size of each part in a multipart upload
DEFAULT_PART_SIZE = str(2 ** (20 + 8))  # 268435456 = 256Mb
