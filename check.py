import time

# Засекаем начало
start_time = time.time()

input_file = "socpanel_dirty.txt"
output_file = "socpanel_clean.txt"

# Счётчики
total_lines = 0
unique_lines = 0
duplicate_lines = 0

# Используем set для хранения уникальных строк
unique_set = set()

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        total_lines += 1
        line = line.strip()  # убираем лишние пробелы и переносы
        if line not in unique_set:
            unique_set.add(line)
            unique_lines += 1
        else:
            duplicate_lines += 1

# Записываем уникальные строки в новый файл
with open(output_file, "w", encoding="utf-8") as f:
    for line in sorted(unique_set):  # можно убрать сортировку, если не нужно
        f.write(line + "\n")

# Засекаем конец
end_time = time.time()
elapsed_time = end_time - start_time

# Выводим статистику
print(f"Обработано строк: {total_lines}")
print(f"Уникальных строк: {unique_lines}")
print(f"Дубликатов: {duplicate_lines}")
print(f"Время выполнения: {elapsed_time:.4f} секунд")
print(f"Уникальные строки сохранены в: {output_file}")
