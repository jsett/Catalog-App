# Catalog App

A web application to store items in categories.

# Install

place your api key in vagrant/catalog/client_secrets.json

Go to the vagrant directory and run the following commands

    vagrant up
    vagrant ssh
    cd /vagrant/catalog
    python view.py


Now go to http://localhost:5000/index in your browser

# api endpoints

All api endpoints only accept json and return json as results.

## Create Category
Endpoint: /api/v1/category/create
Methods Accepted: POST
Arguments:
    {title: title, description: description}
Response:
    {'id': 'category id'}

## Read Category
Endpoint: /api/v1/category/read/<Category Id>
Methods Accepted: GET
Arguments:
    None
Response:
    {"id": "category id", "title": 'category title', "description": 'category description'}

## Update Category
Endpoint: /api/v1/category/update/<Category Id>
Methods Accepted: POST
Arguments:
    {'title': 'Category Title', 'description': 'Category Description'}
Response:
    {"id": 'Category Id', "title": 'Category Title', "description": 'Category Description'})

## Delete Category
Endpoint: /api/v1/category/delete/<Category Id>
Methods Accepted: DELETE
Arguments:
    None
Response:
    {"res": "ok"}

## Create Item
Endpoint: /api/v1/item/create
Methods: POST
Arguments:
{'title': 'item title', 'description': 'item description', 'catagory': 'catagory id'}
Response:
{'id': 'items id'}

Endpoint: /api/v1/item/read/<Item Id>
Methods: GET
Arguments:
    None
Response:
    {"id": 'Item Id', "title": "Item Title", "description": "Item description", "catagory": "Items Category Title", "catagory_id": "Items Category Id", "catagory_description": "Items Category description"}

## Update Item
Endpoint: /api/v1/item/update/<Item Id>
Methods: POST
Arguments:
    {title: title, description: description, catagory: catagory}
Response:
    {"id": 'Item Id', "title": "Item Title", "description": "Item description", "catagory": "Items Category Title", "catagory_id": "Items Category Id", "catagory_description": "Items Category description"}

## Delete Item
Endpoint: /api/v1/item/delete/<Item Id>
Methods: DELETE
Arguments:
    None
Response:
    {"res": "ok"}
