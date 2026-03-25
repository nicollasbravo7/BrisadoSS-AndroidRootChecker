<?php

declare(strict_types=1);

/**
 * Root & Bootloader Detection Scanner for Termux
 * Based on KellerSS ADB System
 */

const C = [
    'rst'      => "\e[0m",
    'bold'     => "\e[1m",
    'branco'   => "\e[97m",
    'cinza'    => "\e[37m",
    'preto'    => "\e[30m\e[1m",
    'vermelho' => "\e[91m",
    'verde'    => "\e[92m",
    'fverde'   => "\e[32m",
    'amarelo'  => "\e[93m",
    'laranja'  => "\e[38;5;208m",
    'azul'     => "\e[34m",
    'ciano'    => "\e[36m",
    'magenta'  => "\e[35m",
];

function c(string ...$nomes): string
{
    return implode('', array_map(fn($n) => C[$n] ?? '', $nomes));
}

function rst(): string
{
    return C['rst'];
}

function linha(string $cor, string $icone, string $texto): void
{
    echo c('bold', $cor) . "  $icone $texto\n" . rst();
}

function ok(string $texto): void      { linha('verde',    '✓', $texto); }
function erro(string $texto): void    { linha('vermelho', '✗', $texto); }
function aviso(string $texto): void   { linha('amarelo',  '⚠', $texto); }
function info(string $texto): void    { linha('fverde',   'ℹ', $texto); }

function secao(string $titulo): void
{
    $sep = str_repeat('─', mb_strlen($titulo) + 4);
    echo "\n" . c('bold', 'azul') . "  ► $titulo\n  $sep\n" . rst();
}

function cabecalho(string $titulo): void
{
    echo "\n" . c('bold', 'ciano') . "  $titulo\n  " . str_repeat('=', mb_strlen($titulo)) . "\n\n" . rst();
}

function inputUsuario(string $mensagem): void
{
    echo c('rst', 'bold', 'ciano') . "  ▸ $mensagem: " . c('fverde');
}

function scannerBanner(): void
{
    echo c('branco') . "
  " . c('branco') . "Root Detection " . c('ciano') . "BugReport Scanner" . c('branco') . "
  " . c('cinza') . "Desenvolvido para Termux" . c('branco') . "

  " . c('ciano') . "Baseado no sistema ADB de KellerSS" . rst() . "\n\n";
}

function adb(string $cmd): string
{
    return trim((string) shell_exec($cmd . ' 2>/dev/null'));
}

function dispositivoConectado(): bool
{
    $output = (string) shell_exec('adb devices');
    $linhas = explode("\n", trim($output));
    foreach ($linhas as $i => $linha) {
        if ($i === 0) continue;
        if (trim($linha) !== '' && strpos($linha, 'device') !== false && strpos($linha, 'unauthorized') === false) {
            return true;
        }
    }
    return false;
}

function conectarADB(): void
{
    system('clear');
    scannerBanner();
    cabecalho("CONEXÃO ADB");
    
    info("Certifique-se que o Depuração sem Fio está ATIVO.");
    inputUsuario("Digite a porta (ex: 38445)");
    $port = trim(fgets(STDIN));
    
    if (!ctype_digit($port) || $port === '') {
        erro("Porta inválida!");
        sleep(2);
        return;
    }

    echo c('bold', 'azul') . "\n  → Tentando conectar em localhost:$port...\n" . rst();
    $res = (string) shell_exec("adb connect localhost:$port 2>&1");
    echo c('cinza') . trim($res) . "\n" . rst();

    if (stripos($res, 'connected') !== false) {
        ok("Conectado com sucesso!");
    } else {
        erro("Falha na conexão.");
    }
    
    echo "\n  Pressione Enter para continuar...";
    fgets(STDIN);
}

function verificarRoot(): void
{
    system('clear');
    scannerBanner();
    cabecalho("INICIANDO SCAN DE BUGREPORT");

    if (!dispositivoConectado()) {
        erro("Dispositivo não conectado via ADB!");
        sleep(2);
        return;
    }

    info("Extraindo bugreport... Isso pode levar alguns segundos.");
    // adb bugreport gera um arquivo .zip
    $tmpFile = "bugreport_tmp_" . time();
    $zipFile = "$tmpFile.zip";
    $txtFile = "$tmpFile.txt";
    
    // Usar adb bugreport com redirecionamento ou arquivo direto
    system("adb bugreport $zipFile");

    if (!file_exists($zipFile)) {
        erro("Falha ao gerar bugreport.");
        echo "\n  Pressione Enter para voltar...";
        fgets(STDIN);
        return;
    }

    info("Analisando dados extraídos...");
    
    // Tentar extrair o arquivo principal (geralmente o maior .txt dentro do zip)
    // No Termux/Linux, podemos usar unzip -p para o stdout e filtrar com grep/php
    
    $deteccoes = [];
    $bootloaderUnlocked = false;
    $searchStrings = ['Tricky Store', 'kernelsu next', 'kernelsu', 'apatch'];

    // Abrir o arquivo de texto extraído do zip para leitura linha a linha (mais memória-friendly)
    system("unzip -p $zipFile > $txtFile");
    $handle = fopen($txtFile, "r");
    
    if ($handle) {
        while (($line = fgets($handle)) !== false) {
            // Regra crucial: Ignorar ActivityTaskManager
            if (stripos($line, 'ActivityTaskManager') !== false) continue;

            // Verificar Bootloader Unlocked
            if (stripos($line, 'ro.boot.flash.locked=0') !== false || 
                stripos($line, 'ro.boot.verifiedbootstate=orange') !== false ||
                stripos($line, 'ro.boot.verifiedbootstate=yellow') !== false) {
                $bootloaderUnlocked = true;
            }

            // Verificar Strings Específicas
            foreach ($searchStrings as $s) {
                if (stripos($line, $s) !== false) {
                    $deteccoes[$s][] = trim($line);
                }
            }
        }
        fclose($handle);
    }

    secao("RESULTADOS DA ANÁLISE");

    if ($bootloaderUnlocked) {
        erro("BOOTLOADER: DESBLOQUEADO (UNLOCKED) DETECTADO!");
    } else {
        ok("Bootloader: Parece estar bloqueado.");
    }

    foreach ($searchStrings as $s) {
        if (isset($deteccoes[$s])) {
            erro("ROOT/BYPASS DETECTADO: [$s]");
            // Mostrar apenas as primeiras 3 ocorrências para não poluir
            $count = 0;
            foreach ($deteccoes[$s] as $occ) {
                if ($count++ < 3) echo c('cinza') . "    > $occ\n" . rst();
            }
        } else {
            ok("Nenhum sinal de: $s");
        }
    }

    // Limpeza
    @unlink($zipFile);
    @unlink($txtFile);

    echo "\n" . c('bold', 'branco') . "  Scan finalizado. Pressione Enter para voltar ao menu...\n" . rst();
    fgets(STDIN);
}

function exibirMenu(): void
{
    $status = dispositivoConectado() 
        ? c('bold', 'verde') . '● Conectado' . rst() 
        : c('bold', 'vermelho') . '○ Desconectado' . rst();

    echo c('bold', 'azul') . "  ╔══════════════════════════╗\n";
    echo c('bold', 'azul') . "  ║      ROOT SCANNER ADB    ║\n";
    echo c('bold', 'azul') . "  ╚══════════════════════════╝\n\n";
    
    echo "  Status ADB: $status\n\n";
    echo c('amarelo') . "  [0] " . c('branco') . "CONECTAR ADB (Porta)\n" . rst();
    echo c('verde')   . "  [1] " . c('branco') . "VERIFICAR ROOT (BugReport)\n" . rst();
    echo c('vermelho'). "  [S] " . c('branco') . "SAIR\n\n" . rst();
}

// Loop Principal
system('clear');
scannerBanner();

while (true) {
    exibirMenu();
    inputUsuario("Escolha uma opção");
    $op = strtoupper(trim(fgets(STDIN)));

    switch ($op) {
        case '0':
            conectarADB();
            system('clear');
            scannerBanner();
            break;
        case '1':
            verificarRoot();
            system('clear');
            scannerBanner();
            break;
        case 'S':
            echo "\n  Saindo...\n\n";
            exit(0);
        default:
            erro("Opção inválida!");
            sleep(1);
            system('clear');
            scannerBanner();
            break;
    }
}
