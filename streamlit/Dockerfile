FROM python:3.12

WORKDIR /home/young/traffic-realtime-threat-analytics/streamlit

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY ./config.toml /root/.streamlit/config.toml

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]

# streamlit>=1.55.0
# pandas>=2.3.3