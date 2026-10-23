PROJECT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
VENV := $(PROJECT_DIR)/.venv
GLOBAL_PYTHON ?= python3
PYTHON := $(VENV)/bin/python

SERVER_START_FILE := $(PROJECT_DIR)/src/main.py
STATIC_DIR := $(PROJECT_DIR)/src/static
APP_NAME := app

.PHONY: help setup run build clean cleanup reset start

start: run

help:
	@echo "Dostępne komendy:"
	@echo ""
	@echo "  make setup    - Tworzy środowisko i instaluje zależności"
	@echo "  make run      - Uruchamia aplikację"
	@echo "  make build    - Buduje samodzielną aplikację"
	@echo "  make clean    - Usuwa artefakty budowania i cache"
	@echo "  make cleanup  - Usuwa artefakty oraz środowisko wirtualne"
	@echo "  make help     - Wyświetla pomoc"

setup: $(VENV)/.setup_done

$(VENV)/.setup_done: $(PROJECT_DIR)/requirements.txt
	$(GLOBAL_PYTHON) -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r $(PROJECT_DIR)/requirements.txt
	$(PYTHON) -m pip install pyinstaller
	@touch $@

run: reset setup
	$(PYTHON) $(SERVER_START_FILE)

build: setup
	$(PYTHON) -m PyInstaller --onefile --clean --noconfirm \
		--name $(APP_NAME) \
		--add-data "$(STATIC_DIR):static" \
		$(SERVER_START_FILE)

clean:
	rm -rf $(PROJECT_DIR)/build
	rm -rf $(PROJECT_DIR)/dist
	rm -f $(PROJECT_DIR)/$(APP_NAME).spec
	find $(PROJECT_DIR)/src -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf $(PROJECT_DIR)/src/__pycache__
	rm -rf $(PROJECT_DIR)/__pycache__

cleanup: clean reset
	rm -rf $(VENV)


reset:
	rm -rf $(PROJECT_DIR)/data
	mkdir $(PROJECT_DIR)/data