"""codewatch.python.web.nosql-injection: request data in MongoDB filters, $where and DynamoDB expressions."""
import pytest

from core import catalog
from core.analyzers.base import Context
from core.analyzers.multi_tools import Semgrep
from tests.test_detection import semgrep_vulnerabilities


def test_json_body_values_in_mongodb_filters(tmp_path):
    """A JSON body's value can be {"$ne": null} (operator injection); a query-string or form value is always text,
    so the same filter built from it stays quiet, as do values made str()/int()/ObjectId(), a body checked by a
    marshmallow schema, an isinstance(str) check, and find() on something that isn't a collection."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "from bson import ObjectId\nfrom bs4 import BeautifulSoup\nfrom flask import Flask, request\n"
        "from flask_pymongo import PyMongo\n\napp = Flask(__name__)\nmongo = PyMongo(app)\n\n\n"
        "@app.post('/login')\n"
        "def login():\n"
        "    data = request.get_json()\n"
        "    user = mongo.db.users.find_one({'username': data['username'], 'password': data['password']})\n"
        "    mongo.db.users.find_one({'username': str(data['username'])})\n"
        "    mongo.db.users.find_one({'_id': ObjectId(data['id'])})\n"
        "    mongo.db.users.find_one({'username': request.args.get('username')})\n"
        "    mongo.db.users.find_one({'username': request.form['username']})\n"
        "    BeautifulSoup(data['html'], 'html.parser').find(data['tag'])\n"
        "    return 'ok'\n\n\n"
        "@app.post('/search')\n"
        "def search():\n"
        "    db = mongo.db\n"
        "    return {'n': db['items'].count_documents(request.json)}\n\n\n"
        "@app.post('/checked')\n"
        "def checked():\n"
        "    name = request.get_json().get('name')\n"
        "    if isinstance(name, str):\n"
        "        mongo.db.users.find_one({'name': name})\n"
        "    clean = UserSchema().load(request.get_json())\n"
        "    mongo.db.users.find_one({'name': clean['name']})\n"
        "    return 'ok'\n"),
        "views.py": (
            "import json\n\nfrom rest_framework.views import APIView\n\n\n"
            "class Items(APIView):\n"
            "    def post(self, request):\n"
            "        self.items_collection.delete_many(request.data)\n\n\n"
            "def items(request):\n"
            "    body = json.loads(request.body)\n"
            "    items_collection.update_one({'owner': body['owner']}, {'$set': {'seen': True}})\n")})
    assert found == {("app.py", 13, "nosql-injection"), ("app.py", 25, "nosql-injection"),
                     ("views.py", 8, "nosql-injection"), ("views.py", 13, "nosql-injection")}


def test_request_text_in_where_and_dynamodb_expressions(tmp_path):
    """$where runs as JavaScript on the server and a DynamoDB expression or PartiQL statement is syntax, so request
    text of any kind counts there. Values given as ExpressionAttributeValues, through boto3's Key()/Attr()
    builders, or as PartiQL Parameters stay quiet."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    found = semgrep_vulnerabilities(tmp_path, {"app.py": (
        "import boto3\nfrom boto3.dynamodb.conditions import Attr, Key\nfrom flask import Flask, request\n\n"
        "app = Flask(__name__)\nclient = boto3.client('dynamodb')\ntable = boto3.resource('dynamodb').Table('users')\n\n\n"
        "@app.route('/users')\n"
        "def users():\n"
        "    name = request.args['name']\n"
        "    db.users.find({'$where': \"this.name == '\" + name + \"'\"})\n"
        "    client.scan(TableName='users', FilterExpression=name + ' = :u',\n"
        "                ExpressionAttributeValues={':u': {'S': name}})\n"
        "    client.execute_statement(Statement=f\"SELECT * FROM users WHERE name = '{name}'\")\n"
        "    client.scan(TableName='users', FilterExpression='username = :u',\n"
        "                ExpressionAttributeValues={':u': {'S': name}})\n"
        "    table.scan(FilterExpression=Attr('owner').eq(name) & Attr('active').eq(True))\n"
        "    table.query(KeyConditionExpression=Key('pk').eq(name))\n"
        "    client.execute_statement(Statement='SELECT * FROM users WHERE name = ?',\n"
        "                             Parameters=[{'S': name}])\n"
        "    return 'ok'\n")})
    assert found == {("app.py", 13, "nosql-injection"), ("app.py", 14, "nosql-injection"),
                     ("app.py", 16, "nosql-injection")}


def test_dynamodb_expression_from_a_parameter_is_a_hotspot(tmp_path):
    """SecurityEval CWE-943 sonar_1: a function nothing calls builds a FilterExpression from its parameter."""
    if not Semgrep().available():
        pytest.skip("semgrep not installed")
    (tmp_path / "dao.py").write_text(
        "import boto3\n\nDYNAMO_CLIENT = boto3.client('dynamodb')\n\n\n"
        "def getUser(username, password):\n"
        "    return DYNAMO_CLIENT.scan(\n"
        "        FilterExpression=username + ' = :u AND password = :p',\n"
        "        ExpressionAttributeValues={':u': {'S': username}, ':p': {'S': password}},\n"
        "        TableName='users')\n")
    ctx = Context(root=tmp_path, files=["dao.py"], semgrep_config="", custom_rules=catalog.custom_semgrep_rules())
    found = {(f.path, f.line, f.rule.rsplit(".", 1)[1], f.type) for f in Semgrep().run(ctx).findings
             if "nothing in the project calls" in f.message}
    assert found == {("dao.py", 8, "nosql-injection", "security_hotspot")}
