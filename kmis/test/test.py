# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from kmip.core.enums import AttributeType
from kmip.core.enums import CredentialType
from kmip.core.enums import ObjectType
from kmip.core.enums import ResultStatus
from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import NameType
from kmip.core.attributes import Name
from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory
from kmip.core.objects import TemplateAttribute, Attribute
from kmip.services.kmip_client import KMIPProxy
from kmis.lib.kmis_enums import (
    KmisResponseTypes,
    KmisResponseStatus,
    KmisResponseCodes)
from kmis.src.templates.kmis_responses import (CertAttrResponse,
                                               KeyAttrResponse,
                                               KeyResponse,
                                               CertResponse,
                                               InvalidResponse)
from kmis.config import (Kms, Misc)
import os
import sys
import traceback
from kmis.src.kmis_core import get_id

'''
client = None
credential_factory = CredentialFactory()
credential_type = CredentialType.USERNAME_AND_PASSWORD
credential_value = {
    'Username': Kms.KMS_USER_NAME, 'Password': Kms.KMS_PASSWORD}
credential = credential_factory.create_credential(credential_type,
                                                  credential_value)
client = KMIPProxy(
    host=Kms.KMS_HOST,
    port=Kms.KMS_PORT,
    cert_reqs=Kms.KMS_CERT_REQUIRES,
    ssl_version=Kms.KMS_SSL_VERSION,
    ca_certs=Kms.KMS_CA_CERTS,
    do_handshake_on_connect=False,
    suppress_ragged_eofs=False,
    username=Kms.KMS_USER_NAME,
    password=Kms.KMS_PASSWORD)

client.open()
print (client, credential)
'''
# get_id(client,credential,'sec-team-rsa')


def test_key(key_name='sec-team-rsa'):
    from kmis.src.kmis_core import get_id, get_kmip_client, get_key_proxy
    a, b = get_kmip_client()
    get_key_proxy(a, b, key_name)

# test_key()


def test_cert(cert_name='safenet-dev'):
    from kmis.src.kmis_core import get_id, get_kmip_client, get_cert_proxy
    a, b = get_kmip_client()
    get_cert_proxy(a, b, cert_name)

test_cert()
