import pymysql
import os
from smartyaddress.smarty_street import SmartyAddressAdaptor
import json

class ColumbiaStudentResource:

    def __init__(self):
        pass

    @staticmethod
    def _get_connection():

        # usr = os.environ.get('DBUSER')
        # pw = os.environ.get('DBPW')
        # h = os.environ.get('DBHOST')

        usr = "admin"
        pw = "dbuserdbuser"
        h = "circuits.cdlehdu4ibgc.us-east-1.rds.amazonaws.com"

        conn = pymysql.connect(
            user=usr,
            password=pw,
            host=h,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
        return conn

    @staticmethod
    def get_by_key(key):

        sql = "SELECT * FROM User_address.columbia_student where uni=%s";
        conn = ColumbiaStudentResource._get_connection()
        cur = conn.cursor()
        res = cur.execute(sql, args=key)
        if res != 1:
            return "Cannot find Uni"
        result = cur.fetchone()

        return result

    @staticmethod
    def get_by_address(key):

        sql = "SELECT * FROM User_address.columbia_student where address_line1 is null and uni=%s";
        conn = ColumbiaStudentResource._get_connection()
        cur = conn.cursor()
        res = cur.execute(sql, args=key)
        if res != 1:
            return 0 #if no address
        result = cur.fetchone()

        return result

    @staticmethod
    def update_by_template(uni, new_resource):
        # print(new_resource)
        sm = SmartyAddressAdaptor()
        res = sm.do_search(new_resource)
        # print("res= ", res)
        if not res:
            return "Invalid Address"
        # print("res= ", res)
        sql = "update f22_databases.students set address_line1=%s, address_line2=%s, city=%s, state=%s where uni=%s"
        conn = ColumbiaStudentResource._get_connection()
        cur = conn.cursor()
        res = cur.execute(sql, (new_resource['street1'], new_resource['street2'], new_resource['city'], new_resource['state'], uni))
        if res != 0:
            return "Address is valid! Updated!"


        return 0

# if __name__ == "__main__":
#     svc = ColumbiaStudentResource()
#     q = {
#         "city": "New York",
#         "state": "NY",
#         "street1": "30 Morningside Drive",
#         "street2": ""
#     }
#     res = svc.update_by_template('dff9', q)
#     print('res= ', json.dumps(res, default=str))




