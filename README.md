# 🧪 Crafting Table

![Whackermelon Logo](whackermelon-claquetteuuuh-crafting-table.png)

A powerful tool for crafting and generating payloads with advanced evasion techniques.

## 🚀 Lancement

Pour lancer le projet avec Docker :

```powershell
docker compose up
```

## 🛠️ API Documentation

L'API est accessible sur le port configuré (par défaut `http://localhost:3001`). Tous les endpoints de modification s'attendent à du JSON.

### 📡 MSFVenom Shellcode Generation
**Endpoint:** `POST /api/msfvenom-shellcode`

Génère du shellcode via msfvenom.

| Champ | Type | Description |
| :--- | :--- | :--- |
| `payload` | String | Format: `^[a-zA-Z0-9\/_]+$` (ex: `windows/x64/meterpreter/reverse_tcp`) |
| `lhost` | String | Adresse IP v4 ou nom de domaine |
| `lport` | String/Number | Port d'écoute (ex: `4444`) |
| `format` | String | Format de sortie (optionnel, ex: `raw`, `c`, `ps1`) |
| `badchars` | String | Caractères à éviter (optionnel, format: `\x00\x0a`) |
| `encoder` | String | Encodeur à utiliser (optionnel) |
| `iterations` | Number | Nombre d'itérations d'encodage (optionnel, min: 1) |

---

### 🔨 Compiler
**Endpoint:** `POST /api/compile`

Compile du code source Nim en exécutable ou DLL.

| Champ | Type | Description |
| :--- | :--- | :--- |
| `code` | String | Le code source à compiler |
| `output` | Enum | `exe` ou `dll` |
| `arch` | Enum | `amd64`, `i386`, `arm64` (Défaut: `amd64`) |
| `flags` | Array<String> | Drapeaux de compilation additionnels (Défaut: `[]`) |

---

### 🛡️ Payload Generator
**Endpoint:** `POST /api/generate-payload`

Génère un loader avancé avec des techniques d'évasion.

> [!IMPORTANT]
> Vous devez fournir soit `shellcode` soit `shellcode_url`, mais pas les deux.

| Champ | Type | Description |
| :--- | :--- | :--- |
| `name` | String | Nom du payload |
| `output` | Enum | `exe` ou `dll` |
| `shellcode` | String | Shellcode brut (optionnel) |
| `shellcode_url` | String | URL vers un shellcode distant (optionnel) |
| `xor_key` | String | Clé de chiffrement XOR (optionnel) |
| `injection_method` | Enum | `fiber`, `thread`, `early_bird` |
| `syscall_evasion` | Enum | `hells_gate`, `none` |
| `anti_sandbox` | Array | Liste de: `cpu_ram`, `timing`, `human_behavior` |
| `anti_debug` | Array | Liste de: `is_debugger_present`, `nt_global_flag` |
| `iat_spoofing` | Array<Object>| Liste d'objets `{ dll, function_name }` |
| `export_function_name`| String | Nom de la fonction exportée pour les DLL (Défaut: `DllMain`) |

---

### 🔍 IAT Functions
**Endpoint:** `GET /api/iat-functions`

Récupère la liste des fonctions disponibles pour le spoofing de l'IAT.

---

## 🎨 Design Theme: Whackermelon
- **Primary Color:** Emerald / Neon Green
- **Background:** Deep Dark / Obsidian
- **Style:** Glassmorphism & Neon Glow