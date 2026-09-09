# AdapTrap Web Dashboard

A real-time monitoring interface for the AdapTrap honeypot-driven firewall system.

## Features

✅ **Real-time Firewall Status**
- Total active BLOCK rules
- Batch 1 and Batch 2 breakdown
- Live nftables query

✅ **Model Performance Metrics**
- Silhouette Coefficient comparison
- Flagging rate monitoring
- Anomaly score distribution

✅ **Threat Intelligence**
- Active BLOCK/ESCALATE/ALLOW counts
- Top 20 blocked threats by anomaly score
- Attack pattern visualization

✅ **Interactive Charts**
- Attack service breakdown (SSH, Telnet, SQL, etc.)
- Bar chart visualization using Chart.js
- Auto-refresh every 30 seconds

## Quick Start

### 1. Start the Dashboard

```bash
cd ~/adaptrap
./start_dashboard.sh
```

### 2. Open in Browser

Navigate to: **http://127.0.0.1:5000**

### 3. Stop the Server

Press `Ctrl+C` in the terminal

## API Endpoints

The dashboard exposes REST API endpoints for integration:

- `GET /api/status` - Overall system status
- `GET /api/metrics` - Model performance metrics
- `GET /api/rules` - List of active BLOCK rules
- `GET /api/attack_patterns` - Attack service statistics

## Architecture

```
adaptrap/
├── dashboard/
│   ├── app.py                 # Flask backend
│   └── templates/
│       └── index.html         # Frontend dashboard
├── start_dashboard.sh         # Startup script
├── batch1_checkpoint.json     # Batch 1 data source
└── batch2_applied_checkpoint.json  # Batch 2 data source
```

## Requirements

- Flask 3.1.3+
- Python 3.10+
- nftables (for live firewall queries)
- Modern web browser (Chrome, Firefox, Edge)

## Troubleshooting

**"Address already in use" error:**
```bash
# Find and kill the process using port 5000
lsof -ti:5000 | xargs kill -9
```

**Firewall status shows error:**
- Ensure you have sudo access
- The dashboard queries `sudo nft list chain inet filter input`
- Configure passwordless sudo for nft commands (optional)

**Charts not loading:**
- Check browser console for JavaScript errors
- Ensure checkpoint JSON files exist in project root
- Verify Flask is running without errors

## For Thesis Defense

**Demo Flow:**
1. Start dashboard before presentation
2. Show real-time firewall status (80 rules)
3. Demonstrate Batch 1 vs Batch 2 comparison
4. Highlight attack patterns (SSH, Telnet, SQL targeting)
5. Show top threats by anomaly score
6. Explain auto-refresh capability

**Key Talking Points:**
- Automated pipeline visualization
- Real-world honeypot data integration
- Continual learning results (Batch 1 → Batch 2)
- End-to-end system demonstration

## Future Enhancements

- [ ] Real-time log streaming
- [ ] Manual rule approval interface for ESCALATE cases
- [ ] Geographic IP mapping
- [ ] Historical trend charts
- [ ] Export reports (PDF/CSV)
- [ ] Email/Slack alerts for high-anomaly threats

---

**Team Monolith** - BS Computer Science  
Asia Pacific College, AY 2025-2026
