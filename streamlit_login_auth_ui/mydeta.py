"""
pip install deta
"""


from deta import Deta


def deta_db(projectkey, dbname):
    pk = Deta(projectkey)
    return pk.Base(dbname)
