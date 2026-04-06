# watts-mqtt

A bridge between the Watts Home cloud API and Home Assistant via MQTT.

Forked from [AlbinoDrought/creamy-waha](https://github.com/AlbinoDrought/creamy-waha) with the following fixes and additions:
- Fixed OAuth2 scope encoding bug that prevented login
- Fixed current temperature reporting — Tekmar 564 uses a floor sensor (`Sensors.Floor`), not a room sensor (`Sensors.Room`). The original code only checked the room sensor, which is always `Absent` on these devices.
- Added proper error checking on the Azure B2C SelfAsserted login response (HTTP 200 masks JSON-level errors)
- Added `docker-compose.yml` for local deployment

## How it works

```
Tekmar 564 thermostats → Watts Home Cloud API → watts-mqtt → MQTT → Home Assistant
```

Devices are published using the Home Assistant MQTT autodiscovery protocol and appear automatically as `climate` entities.

## Supported features

- Watts Home login with automatic token refresh
- Tekmar 564:
  - Current floor temperature
  - Current humidity (if sensor present)
  - Outdoor temperature (if sensor present)
  - HVAC mode: heat, cool, heat/cool, off
  - Current action: heating, cooling, idle, off
  - Fan state: auto, on, schedule
  - Set temperature setpoint via MQTT
  - Set HVAC mode via MQTT
  - Set fan mode via MQTT

## Prerequisites

- Tekmar 564 thermostats registered in the [Watts Home app](https://www.watts.com/our-products/controls-and-management-systems/controls/watts-home)
- MQTT broker (e.g. the [Mosquitto add-on](https://github.com/home-assistant/addons/tree/master/mosquitto) in Home Assistant)
- Docker

## Setup

### 1. Clone and configure

```sh
git clone https://github.com/apbb2/watts-mqtt
cd watts-mqtt
mkdir data
```

Create a `.env` file with your Watts Home credentials:

```env
WAHA_USER=your@email.com
WAHA_PASS=your-watts-home-password
```

### 2. Configure docker-compose.yml

Edit `docker-compose.yml` with your MQTT broker address and credentials:

```yml
services:
  watts-mqtt:
    build: .
    container_name: watts-mqtt
    restart: unless-stopped
    env_file:
      - .env
    environment:
      - WAHA_MQTT_BROKER=tcp://your-ha-ip:1883
      - WAHA_MQTT_USER=your-mqtt-user
      - WAHA_MQTT_PASS=your-mqtt-password
      - WAHA_TOKENS_PATH=/data/tokens.json
    volumes:
      - ./data:/data
```

> **Note:** The Mosquitto add-on in Home Assistant requires authentication by default. Create a dedicated HA user for MQTT and use those credentials for `WAHA_MQTT_USER` / `WAHA_MQTT_PASS`.

### 3. Build and run

```sh
docker compose up --build -d
```

On first run it will authenticate with Watts Home and save tokens to `data/tokens.json`. Subsequent starts will reuse and auto-refresh the saved tokens.

### 4. Home Assistant

Make sure the MQTT integration is enabled in Home Assistant (`default_config:` in `configuration.yaml` includes it). Your Tekmar 564 devices will appear automatically under **Settings → Devices & Services → MQTT** as climate entities.

## Configuration reference

| Env Var | Description | Default |
|---|---|---|
| `WAHA_USER` | Watts Home account email | Required |
| `WAHA_PASS` | Watts Home account password | Required |
| `WAHA_MQTT_BROKER` | MQTT broker URI | `tcp://localhost:1883` |
| `WAHA_MQTT_USER` | MQTT username | Empty |
| `WAHA_MQTT_PASS` | MQTT password | Empty |
| `WAHA_TOKENS_PATH` | Path to store auth tokens | `tokens.json` |

## MQTT topics

Each device publishes and subscribes on `watts/<device-id>/`:

| Topic | Direction | Description |
|---|---|---|
| `watts/<id>/availability` | publish | `online` or `offline` |
| `watts/<id>/current_temp` | publish | Current floor temperature |
| `watts/<id>/mode/state` | publish | Current HVAC mode |
| `watts/<id>/action` | publish | Current action (heating/cooling/idle) |
| `watts/<id>/temp/state` | publish | Target temperature |
| `watts/<id>/fan/state` | publish | Fan mode |
| `watts/<id>/mode/set` | subscribe | Set HVAC mode |
| `watts/<id>/temp/set` | subscribe | Set target temperature |
| `watts/<id>/fan/set` | subscribe | Set fan mode |

## License

CC0-1.0 — see [LICENSE](LICENSE). Original work by [AlbinoDrought](https://github.com/AlbinoDrought).
