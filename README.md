# Xray Access View
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)

**Xray Access View**

### Запуск в основном режиме
```bash
python3 <(curl -sL https://github.com/hzhexee/xray-access-view/raw/main/view.py)
```
![image](static/output.jpg)

### Запуск в основном режиме с выводом не только доменов, но и ip
```bash
python3 <(curl -sL https://github.com/hzhexee/xray-access-view/raw/main/view.py) --ip
```

### Запуск в режиме сводки
```bash
python3 <(curl -sL https://github.com/hzhexee/xray-access-view/raw/main/view.py) --summary
```
![image](static/summary-output.jpg)

### Запуск в режиме сводки, с выводом только тех ip, что сейчас подключены к серверу
```bash
python3 <(curl -sL https://github.com/hzhexee/xray-access-view/raw/main/view.py) --online
```
