PROJECT_NAME='CloudGuard'
SERVICES=['S3','IAM','VPC']
LOGGER_PATH='logs'
SEPARATOR = "-" * 60
ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

ADMIN_PORTS = [22, 3389]
DATABASE_PORTS = [3306, 5432, 1433, 6379]
PUBLIC_WEB_PORTS = [80, 443]
PORTS=ADMIN_PORTS+DATABASE_PORTS+PUBLIC_WEB_PORTS
