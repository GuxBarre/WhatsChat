@echo off
cd /d "%~dp0"
echo --- INICIANDO SISTEMA WHATSCHAT SEGURO ---

:: 1. Certificados
if not exist "certs\server.key" (
    echo [SISTEMA] Gerando certificados...
    python src/gera_certs.py
)

:: 2. Usuarios
if not exist "users.txt" (
    echo [SISTEMA] Criando usuario inicial...
    python registrar.py
)

:: 3. Inicia Servidor
echo [SISTEMA] Iniciando Servidor...
start "WhatsChat SERVER" python src/server.py

:: 4. Aguarda o servidor subir (importante para Diffie-Hellman)
echo Aguardando servidor iniciar...
timeout /t 5 >nul

:: 5. Inicia DOIS clientes para teste
echo [SISTEMA] Iniciando Cliente GUSTAVO...
if exist "src\client_gui.py" (
    start "Cliente 1" python src/client_gui.py
    timeout /t 2 >nul
    start "Cliente 2" python src/client_gui.py
) else (
    if exist "src\cliente_GUI.py" (
        start "Cliente 1" python src/cliente_GUI.py
        timeout /t 2 >nul
        start "Cliente 2" python src/cliente_GUI.py
    ) else (
        echo [ERRO] Nao achei o arquivo do cliente na pasta src!
        pause
    )
)

echo [SISTEMA] Sistema online. Use as janelas abertas.