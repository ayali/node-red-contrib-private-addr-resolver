# node-red-contrib-private-addr-resolver

A Node-RED node to resolve private Bluetooth Low Energy (BLE) mac addresses, helping identify devices like 
iPhones and iPads that use Resolvable Private Addresses (RPAs) as virtual mac addresses.

## Overview

Bluetooth Low Energy (BLE) devices, such as iPhones, use Resolvable Private Addresses (RPAs) to enhance privacy by periodically 
changing their mac addresses. These RPAs are generated using an Identity Resolving Key (IRK) and can be resolved to confirm 
a device’s identity. 

The `node-red-contrib-private-addr-resolver` node simplifies this process in Node-RED by taking a mac address and an IRK as inputs, 
performing the AES-CMAC computation, and routing the mac address to one of two outputs based on whether it matches the IRK.

This node is ideal for home automation setups, IoT projects, or any application needing to track BLE devices with 
rotating mac addresses, such as detecting the presence of your iPhone in a specific area.

## Features
- **Input Validation**: Accepts mac_address and irk via `msg.payload` or node configuration.
- **Dual Outputs**:
  - Output 1: Matching mac_address (the mac address belongs to the device with the specified IRK)
  - Output 2: Non-matching mac_address
- **Easy Integration**: Works seamlessly with BLE scanning nodes like `node-red-contrib-ble` or `node-red-contrib-noble`.

## Installation

Install via the Node-RED Manage Palette or npm.

### Via Manage Palette
1. Open Node-RED in your browser (e.g., `http://localhost:1880`).
2. Go to **Menu** → **Manage Palette** → **Install** tab.
3. Search for `node-red-contrib-private-addr-resolver`.
4. Click **Install** and restart Node-RED when prompted.

### Via npm
In your Node-RED user directory (typically `~/.node-red` or `/data` in Docker):
```bash
npm install node-red-contrib-private-addr-resolver
