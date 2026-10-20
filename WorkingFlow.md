Here’s a practical workflow for using PhantomPot. It accepts arbitrary credentials as a honeypot, records activity, and analyzes completed sessions. Run the commands from the project directory.

1. **Start the honeypot** in Terminal 1:

   ```bash
   .venv/bin/python src/main.py
   ```

   It listens on SSH `2222`, HTTP `8888`, FTP `2121`, and Telnet `2323`. Leave this terminal running; press **Ctrl+C** here when you want to stop it.

2. **Generate sample traffic** in Terminal 2:

   ```bash
   .venv/bin/python scripts/simulate_multi_protocol.py
   ```

   Or open `http://localhost:8888` in your browser and submit any values on the HTTP login form. PhantomPot records the attempt; it has no real HTTP account.

3. **View recorded activity** in Terminal 2 or 3:

   ```bash
   tail -f logs/sessions.jsonl
   ```

4. **Open the dashboard** in another terminal:

   ```bash
   .venv/bin/streamlit run dashboard/app.py
   ```

   Then visit [http://localhost:8501](http://localhost:8501). The dashboard reads `logs/sessions.jsonl`.

5. **Optionally run the KPI evaluation** while the honeypot is running:

   ```bash
   .venv/bin/python scripts/evaluate_objective4.py --quick --output eval_report.json
   ```

   This simulates scenarios and saves a report to `eval_report.json`.

Stop the dashboard in its terminal with **Ctrl+C** as well.