# XILLEN Memory Analyzer

## Описание
Мощный Rust инструмент для анализа памяти и цифровой криминалистики. Инструмент предоставляет комплексные возможности для анализа живых процессов, дампов памяти, обнаружения вредоносного ПО и проведения криминалистических исследований.

## Возможности
- **Live Memory Analysis**: Анализ памяти работающих процессов в реальном времени
- **Memory Dump Analysis**: Анализ файлов дампов памяти различных форматов
- **Pattern Scanning**: Поиск паттернов и строк в памяти
- **Forensics Analysis**: Криминалистический анализ систем
- **Cryptographic Operations**: Шифрование/дешифрование областей памяти
- **Process Analysis**: Детальный анализ процессов и модулей
- **Memory Regions**: Анализ областей памяти и их свойств
- **String Extraction**: Извлечение строк из памяти
- **Network Analysis**: Анализ сетевой активности процессов
- **Registry Analysis**: Анализ реестра Windows
- **File System Analysis**: Анализ файловой системы
- **Malware Detection**: Обнаружение и анализ вредоносного ПО
- **Integrity Checking**: Проверка целостности памяти
- **Performance Profiling**: Профилирование производительности
- **Comprehensive Reporting**: Генерация детальных отчетов

## Установка

### Требования
- Rust 1.70+ (stable)
- Cargo (входит в Rust)
- Права администратора/root для анализа памяти

### Сборка
```bash
git clone https://github.com/BengaminButton/xillen-memory-analyzer
cd xillen-memory-analyzer
cargo build --release
```

### Установка
```bash
cargo install --path .
```

## Использование

### Базовые команды
```bash
# Анализ живого процесса
xillen-memory-analyzer live --pid 1234 --verbose

# Анализ дампа памяти
xillen-memory-analyzer dump --file memory.dmp --format raw

# Поиск паттернов
xillen-memory-analyzer scan "password" --regex --case-sensitive

# Криминалистический анализ
xillen-memory-analyzer forensics --target /path/to/system --artifacts --timeline
```

### Подробные примеры

#### Анализ живого процесса
```bash
# Анализ процесса по PID
xillen-memory-analyzer live --pid 1234 --sample-size 1000 --verbose

# Анализ процесса по имени
xillen-memory-analyzer live --process-name "chrome.exe" --sample-size 500
```

#### Анализ дампа памяти
```bash
# Анализ полного дампа
xillen-memory-analyzer dump --file crash.dmp --format minidump

# Анализ части дампа
xillen-memory-analyzer dump --file memory.dmp --offset 0x1000 --size 4096
```

#### Поиск паттернов
```bash
# Поиск простой строки
xillen-memory-analyzer scan "admin" --case-sensitive

# Поиск по регулярному выражению
xillen-memory-analyzer scan "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b" --regex

# Ограничение результатов
xillen-memory-analyzer scan "password" --max-results 100
```

#### Криминалистический анализ
```bash
# Полный анализ системы
xillen-memory-analyzer forensics --target /mnt/evidence --artifacts --timeline --report report.html

# Анализ конкретных артефактов
xillen-memory-analyzer forensics --target /path/to/evidence --artifacts
```

#### Криптографические операции
```bash
# Шифрование области памяти
xillen-memory-analyzer crypto encrypt --algorithm aes-256-gcm --key "secret_key" --input memory.bin --output encrypted.bin

# Дешифрование области памяти
xillen-memory-analyzer crypto decrypt --algorithm aes-256-gcm --key "secret_key" --input encrypted.bin --output decrypted.bin
```

#### Анализ процессов
```bash
# Список всех процессов
xillen-memory-analyzer process --list

# Информация о конкретном процессе
xillen-memory-analyzer process --info 1234

# Модули процесса
xillen-memory-analyzer process --modules 1234

# Дескрипторы процесса
xillen-memory-analyzer process --handles 1234
```

#### Анализ областей памяти
```bash
# Анализ областей конкретного процесса
xillen-memory-analyzer regions --pid 1234 --detailed --permissions --protection

# Общий анализ областей памяти
xillen-memory-analyzer regions --detailed
```

#### Извлечение строк
```bash
# Извлечение строк из файла
xillen-memory-analyzer strings --target memory.bin --min-length 8 --encoding utf8 --output strings.txt

# Извлечение строк из процесса
xillen-memory-analyzer strings --target "chrome.exe" --min-length 4
```

#### Анализ сети
```bash
# Анализ сетевых соединений процесса
xillen-memory-analyzer network --pid 1234 --connections --sockets --dns

# Общий анализ сети
xillen-memory-analyzer network --connections
```

#### Анализ реестра (Windows)
```bash
# Анализ всех кустов реестра
xillen-memory-analyzer registry --hives --values --timeline

# Анализ конкретных ключей
xillen-memory-analyzer registry --keys "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows" --values
```

#### Анализ файловой системы
```bash
# Анализ файловой системы
xillen-memory-analyzer filesystem --target /path/to/disk --deleted --slack --metadata

# Поиск удаленных файлов
xillen-memory-analyzer filesystem --target /dev/sda --deleted
```

#### Обнаружение вредоносного ПО
```bash
# Анализ с использованием YARA правил
xillen-memory-analyzer malware --target suspicious.exe --signatures --behavior --yara rules.yar

# Карантин подозрительных файлов
xillen-memory-analyzer malware --target malware.exe --quarantine /quarantine/
```

#### Проверка целостности
```bash
# Создание базовой линии
xillen-memory-analyzer integrity --baseline baseline.json --checksums --signatures

# Сравнение с базовой линией
xillen-memory-analyzer integrity --baseline baseline.json --current current.json
```

#### Профилирование производительности
```bash
# Профилирование в течение 60 секунд
xillen-memory-analyzer profile --duration 60 --interval 1 --metrics cpu,memory,io --output profile.json

# Непрерывное профилирование
xillen-memory-analyzer profile --metrics cpu,memory
```

#### Генерация отчетов
```bash
# Генерация HTML отчета
xillen-memory-analyzer report --target /path/to/evidence --format html --output report.html

# Использование пользовательского шаблона
xillen-memory-analyzer report --target evidence --template custom.tpl --output custom_report.html
```

## Конфигурация

### config.json
```json
{
  "analysis": {
    "max_sample_size": 10000,
    "timeout": 30000,
    "threads": 4
  },
  "crypto": {
    "default_algorithm": "aes-256-gcm",
    "key_derivation": "pbkdf2",
    "iterations": 100000
  },
  "forensics": {
    "artifact_types": ["processes", "files", "registry", "network"],
    "timeline_format": "json",
    "hash_algorithms": ["md5", "sha1", "sha256"]
  },
  "output": {
    "default_format": "json",
    "compression": true,
    "encryption": false
  }
}
```

## Поддерживаемые алгоритмы шифрования
- **AES**: AES-128, AES-192, AES-256 (CBC, GCM, CTR)
- **ChaCha20**: ChaCha20-Poly1305
- **DES**: DES, 3DES
- **Blowfish**: Blowfish с различными режимами

## Поддерживаемые форматы дампов
- **Raw**: Сырые дампы памяти
- **Minidump**: Windows minidump файлы
- **Hiberfil**: Файлы гибернации Windows
- **Pagefile**: Файлы подкачки
- **Crash Dumps**: Дампы аварий

## Выходные форматы
- **JSON**: Структурированные данные
- **HTML**: Веб-отчеты
- **CSV**: Табличные данные
- **TXT**: Текстовые отчеты
- **XML**: XML формат

## Безопасность
⚠️ **ВНИМАНИЕ**: Используйте только для тестирования собственных систем или с явного разрешения владельцев. Анализ памяти может содержать конфиденциальную информацию.

## Требования
- Rust 1.70+
- Права администратора/root
- Достаточно оперативной памяти для анализа
- Знание системной архитектуры

## Авторы
- **@Bengamin_Button** - Основной разработчик
- **@XillenAdapter** - Технический консультант

## Ссылки
- 🌐 **Website**: https://benjaminbutton.ru/
- 🔗 **Organization**: https://xillenkillers.ru/
- 📱 **Telegram**: t.me/XillenAdapter

## Лицензия
MIT License - свободное использование и модификация

## Поддержка
Для вопросов и предложений обращайтесь через Telegram или создавайте Issues на GitHub.

---
*XILLEN Memory Analyzer - профессиональный инструмент для анализа памяти и цифровой криминалистики*
