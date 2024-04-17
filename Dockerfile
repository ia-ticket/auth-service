FROM python:3.9

WORKDIR /auth-service

COPY ./requirements.txt /auth-service/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . /auth-service

EXPOSE 3000

CMD ["python3", "auth.py"]
