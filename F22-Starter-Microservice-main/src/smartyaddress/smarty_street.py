# -*- coding: utf-8 -*-
import os

from smartystreets_python_sdk import StaticCredentials, exceptions, ClientBuilder
from smartystreets_python_sdk.us_street import Lookup as StreetLookup
import uuid
import json


class SmartyAddressAdaptor:

    # auth_id = os.environ['SMARTY_AUTH_ID']
    # auth_token = os.environ['SMARTY_AUTH_TOKEN']
    auth_id = '649b5a69-75e7-0203-a5a2-e60bcff8de77'
    auth_token = '2GDsAsN5D5QMB36AhSYB'

    credentials = StaticCredentials(auth_id, auth_token)

    def __init__(self, candidates=None):
        self.candidates = candidates
        if self.candidates:
            self._set_dictionay()

    def _set_dictionay(self):
        self.candidates_dic = {}
        for i in self.candidates:
            self.candidates_dic[str(uuid.uuid4())] = i

    def do_lookup(self, lookup):
        client = ClientBuilder(SmartyAddressAdaptor.credentials).with_licenses(["us-core-cloud"]).build_us_street_api_client()
        client.send_lookup(lookup)
        try:
            client.send_lookup(lookup)
        except exceptions.SmartyException as err:
            print(err)
            self.candidates = None
            return

        self.candidates = lookup.result
        self._set_dictionay()

    def do_search(self, address_fields):
        lookup = StreetLookup()

        lookup.street = address_fields.get('street1', None)
        lookup.street2 = address_fields.get('street2', None)
        lookup.city = address_fields.get('city', None)
        lookup.state = address_fields.get('state', None)
        lookup.zipcode = address_fields.get('zipcode', None)

        self.do_lookup(lookup)

        if self.candidates:
            res = len(self.candidates)
        else:
            res = None

        return res

    def to_json(self):

        result_all = {}

        for k, c in self.candidates_dic.items():
            result = {}
            base_fields = dir(c)
            for f in base_fields:
                if f not in ['components', 'metadata'] and f[0] != '_':
                    result[f] = getattr(c, f, None)

            comonents_fields = dir(c.components)
            result['components'] = {}
            for f in comonents_fields:
                if f[0] != '_':
                    result['components'][f] = getattr(c.components, f, None)

            metadata_fields = dir(c.metadata)
            result['metadata'] = {}
            for f in metadata_fields:
                if f[0] != '_':
                    result['metadata'][f] = getattr(c.metadata, f, None)
            result_all[c.delivery_point_barcode] = result

        return result_all



# if __name__ == "__main__":
#     sm = SmartyAddressAdaptor()
#     q = {
#         "city": "New York",
#         "state": "NY",
#         "street1": "30 Morningside Drive"
#     }
#     res = sm.do_search(q)
#     print("res= ", res)
#     if res >= 1:
#         print("Candidates:\n")
#         print(json.dumps(sm.to_json(), indent=2, default=str))