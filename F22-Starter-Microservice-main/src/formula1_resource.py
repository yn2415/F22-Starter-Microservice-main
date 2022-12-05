import pymysql
import os

class Formula1Resource():

    def __int__(self):
        pass


    def _get_connection(self):

        usr = os.environ.get('DBUSER')
        pw = os.environ.get('DBPW')
        h = os.environ.get('DBHOST')

        conn = pymysql.connect(
            user=usr,
            password=pw,
            host=h,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
        return conn

    def get_by_key(self, key):

        sql = "SELECT name, location, country FROM microservice1.circuits where `circuitRef`=%s";
        conn = self._get_connection()
        cur = conn.cursor()
        res = cur.execute(sql, args=key)
        if res == 1:
            result = cur.fetchone()
        else:
            result = "Nothing found"

        return result

    def create_by_template(self, new_resource):
        print(new_resource['circuitRef'])
        if self.get_by_key(new_resource['circuitRef'])!="Nothing found":
            return ("already exist")
        sql = "insert into microservice1.circuits(circuitId, circuitRef, name, location, country, lat, lng, alt, url) values ((SELECT MAX(circuitID) FROM microservice1.circuits c)+1,"
        for k, v in new_resource.items():
            sql += '"' + str(v) + '", '
        sql = sql[0:-2]
        sql += ')'
        print(sql)
        conn = self._get_connection()
        cursor = conn.cursor()
        res = cursor.execute(sql)

        if res != 0:
            result = new_resource['circuitRef']
        else:
            result = 0

        return result

    def delete_by_ref(self, ref):
        sql = "delete from microservice1.circuits where circuitRef=%s"
        conn = self._get_connection()
        cursor = conn.cursor()
        res = cursor.execute(sql, args=ref)

        if res != 0:
            result = 1
        else:
            result = 0

        return result

