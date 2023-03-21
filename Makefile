all: install

run: venv/bin/python3 translations/de/LC_MESSAGES/messages.mo translations/en/LC_MESSAGES/messages.mo
	SECRET_KEY=secret FLASK_ENV=development ./venv/bin/python Filer.py -P 5000 --host=0.0.0.0

translations/en/LC_MESSAGES/messages.mo: translations/en/LC_MESSAGES/messages.po
	./venv/bin/pybabel compile -d translations -l en

translations/de/LC_MESSAGES/messages.mo: translations/de/LC_MESSAGES/messages.po
	./venv/bin/pybabel compile -d translations -l de

rebuild_po:
	./venv/bin/pybabel extract -F babel.cfg -o messages.pot .
	./venv/bin/pybabel update -i messages.pot -d translations
	-rm translations/en/LC_MESSAGES/messages.mo translations/de/LC_MESSAGES/messages.mo:

venv/bin/python3:
	python3 -m venv ./venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
