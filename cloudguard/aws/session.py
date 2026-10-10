import os
import boto3

from dotenv import load_dotenv

load_dotenv()


class CloudGuardSession:
    def __init__(self, session, endpoint_url=None):
        self._session = session
        self._endpoint_url = endpoint_url

    def client(self, service_name, **kwargs):
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url

        return self._session.client(service_name, **kwargs)


def create_session(
    region=None,
    endpoint_url=None,
    aws_access_key_id=None,
    aws_secret_access_key=None,
):
    endpoint_url = endpoint_url or os.getenv("AWS_ENDPOINT_URL")

    session = boto3.Session(
        region_name=region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )

    return CloudGuardSession(
        session=session,
        endpoint_url=endpoint_url,
    )
