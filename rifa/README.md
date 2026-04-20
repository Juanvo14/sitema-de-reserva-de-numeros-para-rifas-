# 🎟️ NeoRifa — Sistema de Reservas

Aplicación de rifa con interfaz neo-oscura. Backend Python/Flask, frontend HTML/CSS.

## Instalación rápida

```bash
# 1. Instalar dependencias
pip install flask

# 2. Ejecutar
python app.py
```

Luego abre tu navegador en: **http://localhost:5000**

## Credenciales iniciales

| Rol   | Campo     | Valor     |
|-------|-----------|-----------|
| Admin | Usuario   | admin     |
| Admin | Contraseña| admin123  |

*(Puedes cambiar la contraseña desde el panel admin)*

## Estructura del proyecto

```
rifa/
├── app.py                  # Backend Flask
├── data.json               # Base de datos (se crea automático)
├── requirements.txt
└── templates/
    ├── base.html           # Layout base con diseño neo
    ├── login_selector.html # Pantalla de selección de acceso
    ├── login_admin.html    # Login administrador
    ├── login_usuario.html  # Login usuario
    ├── admin_panel.html    # Panel de administración
    ├── admin_lista.html    # Lista completa de reservas
    └── reservar.html       # Vista de reserva para usuarios
```

## Colores de los números

| Color   | Significado                          |
|---------|--------------------------------------|
| 🟢 Verde | Número libre (disponible)            |
| 🔴 Rojo  | Número reservado (confirmado)        |
| 🟡 Amarillo | En veremos (pendiente de confirmar) |

## Flujo de uso

1. **Usuario** ingresa con nombre y teléfono
2. Selecciona un número verde disponible
3. El número queda en **amarillo (en veremos)**
4. **Admin** confirma el pago → pasa a **rojo (reservado)**

## Funciones del Admin

- Configurar título, premio, valor y fecha de la rifa
- Confirmar, liberar o reservar cualquier número manualmente
- Ver lista completa con filtros por estado
- Cambiar contraseña de administrador
