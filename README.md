# SelfCloud
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000
Otwórz http://localhost:8000. Przy pierwszym starcie hasło admina zostanie wypisane w konsoli
(lub ustaw ADMIN_USER / ADMIN_PASSWORD). Dane: katalog `data/` (zmiana: DATA_DIR).


# Aby uruchomić kontener:
```bash
docker run --name mycloud -p 8080:8080 \
  -v mycloud-data:/data \
  -v /path/to/cert/mycloud.crt:/certs/mycloud.crt:ro \
  -v /path/to/key/mycloud.key:/certs/mycloud.key:ro \
  -e ADMIN_USER=admin \
  -e ADMIN_PASSWORD='12345678' \
  -e SSL_CERT_FILE="/certs/mycloud.crt" \
  -e SSL_KEY_FILE="/certs/mycloud.key" \
  mycloud
```