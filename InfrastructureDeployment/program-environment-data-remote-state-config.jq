[inputs | sub("\\r$";"") | capture("^(?<key>[^=]*)=(?<value>.*)")]
| from_entries
| .
