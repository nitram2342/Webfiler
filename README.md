Webfiler
========

This project leverages the powers of Flask and Flask-Dropzone to provide for a simple self hosted user upload space manager.

If you're a lawyer, doctor, or have a small company and need your clients/patients/customers to share some documents with you (and only you), you can create spaces for them with just a click, pass them their passwords and use your and their web browsers as upload and file list interface. Each installation also gets a Public space for your documents to share with everyone.

Webfiler's mission is to minimize dependencies and work with minimal lines of code so you can easily verify the source yourself.

Installation
============

Currently, Webfiler comes with a Makefile which sets everything up for you. After cloning the project, just type `make run` and after installing all dependencies, a sneak preview server will run at http://localhost:5000/. This will also create work directories under a data directory that defaults to './Daten'.

Web server integration
======================

Webfiler generates htpasswd files to protect your spaces. Webfiler has a [sample nginx config](nginx.conf.sample) you can use. Porting it to Apache will not work without changing the code.


Using Google Authenticator
===========================

File downloads can be restriced to a second factor token provided by the Google Authenticator. When you create a new user, a token seed is generated. Download the seed as QR code, hand it over to your clients/patients/customers. It requires a bit of background knowledge to use a second factor. Depending on the people using the File, you may disable it for certain users.

In order to create a seed for the admin user, just create a temporary user such as "myfiler-admin", download the user's QR code, and move the "myfiler-admin.token" file to the "admin.token" file using shell access on the web server. Delete the "myfiler-admin" user afterwards. The user name will later appear in the authenticator mobile app. Therefore, a meaningful username is recommended.

License
=======

Webfiler is released under Beerware.
