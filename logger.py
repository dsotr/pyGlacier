import sqlite3
import datetime
import datetime

def convert_dict_keys_to_alphanum(source_dict):
    return dict(map(
        lambda x: (x[0].lower().replace('-', '_'), x[1]),
        source_dict.items())
    )



class Logger():
    def __init__(self, database_path):
        self.database_path = database_path
        self.conn = None
        cursor = self.get_cursor()
        # cursor.execute('''drop table if exists requests''')
        # cursor.execute('''drop table if exists responses''')
        cursor.execute(
            '''create table if not exists requests (
            id integer primary key,
            content_length text,
            date text,
            host text,
            authorization text,
            x_amz_glacier_version text,
            x_amzn_requestid text,
            x_amz_date text,
            x_amz_content_sha256 text,
            x_amz_sha256_tree_hash text,
            headers text
            )'''
        )
        cursor.execute(
            '''create table if not exists responses (
            id integer primary key,
            content_length text,
            content_type text,
            date text,
            x_amzn_requestid text,
            x_amz_sha256_tree_hash text,
            headers text
            )'''
        )
        self.commit_and_close()

    def get_cursor(self):
        self.conn = sqlite3.connect(self.database_path)
        return self.conn.cursor()

    def commit_and_close(self):
        self.conn.commit()
        self.conn.close()

    def log(self, table, headers):
        cursor = self.get_cursor()
        sql_friendly_headers = convert_dict_keys_to_alphanum(headers)
        ####temp#######
        #sql_friendly_headers.pop('authorization')
        # add the original headers dictionary to the table
        sql_friendly_headers['headers'] = str(headers)
        columns = ', '.join(sorted(sql_friendly_headers.keys()))
        placeholders = ':' + ', :'.join(sorted(sql_friendly_headers.keys()))


        query = "INSERT INTO %s (%s) VALUES (%s)" % (table, columns, placeholders)
        # query = r"""INSERT INTO %s (request_id, date) VALUES (:request-id, :date)""" % (table,)
        print(query)
        print(sql_friendly_headers)
        cursor.execute(query, sql_friendly_headers)
        self.commit_and_close()

    def log_request(self, headers):
        self.log('requests', headers)

    def log_response(self, headers):
        self.log('responses', headers)

if __name__ == '__main__':
    logger = Logger('example.db')
    headers = {'authorization': datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S')}
    logger.log('requests', headers)
