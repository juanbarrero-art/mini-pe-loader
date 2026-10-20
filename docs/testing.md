# Pruebas

Entorno usado: Windows 11 x64 (build 26100), MSVC x64, flags `/W4 /O2 /MT`.

```bat
scripts\build.bat
```

| Prueba | Resultado |
|---|---|
| `bin\miniload.exe bin\silent.exe` | `exit 7`; relocations aplicadas; imports resueltos; `.pdata` registrado |
| `bin\miniload.exe bin\seh.exe` | `exit 7`: la excepción se captura (el `.pdata` funciona) |
| `bin\miniload.exe bin\hello.exe` | MessageBox; `exit 0` al cerrar |

Los números exactos (relocations, imports, entradas `.pdata`) dependen del compilador y de
la build. Lo importante es que el loader imprima cada fase y que el payload termine con el
código esperado.

## Nota sobre `.pdata`

`RtlLookupFunctionEntry` con `NULL` en el tercer argumento compila, pero provoca
`0xC0000005` en esta build. El loader pasa una tabla de historial a cero. Si tu cabecera
de user-mode no define `UNWIND_HISTORY_TABLE`, replica la estructura (contador, límites y
12 entradas) o usa un buffer a cero del tamaño adecuado.
