# Autonomous Security Tool - Stateful Crawler

A Playwright-based stateful crawler designed to navigate single-page applications (SPAs), handle authentication, and discover endpoints, GraphQL schemas, and forms.

## User Requirements (Prerequisites)

Before running the crawler, you must:
1. Ensure Python 3.10+ is installed on your system.
2. Install the required Python packages.
3. Install Playwright browsers (`playwright install chromium`).
4. Provide valid login credentials in the `Crawler.py` file under the `CREDENTIAL_MATRIX` dictionary. For example:
   ```python
   CREDENTIAL_MATRIX = {
       "User": ("spk@csii.in", "Spk@1234"),
   }
   ```
5. Ensure the target application URL in `TARGET_BASE_URL` inside `Crawler.py` is accurate.

## Configuration (Hardcoded Values)

Currently, the crawler relies on several hardcoded variables defined at the top of `Crawler.py`. You will need to revisit and update these when targeting a different application:

- **`TARGET_BASE_URL`**: The starting URL of your application.
- **`LOGIN_URL`**: The explicit URL where the login form is located.
- **`USERNAME_SELECTOR` & `PASSWORD_SELECTOR`**: The CSS selectors used to locate the login fields (e.g., `input[type='email']`).
- **`SUBMIT_SELECTOR`**: The CSS selector for the login button.
- **`SCOPE_HOSTS`**: An array of allowed domains (e.g., `["csii.in"]`). The crawler will not follow links outside these domains.
- **`EXCLUDED_PATHS`**: Paths the crawler should strictly avoid navigating to, such as `["/logout", "/signout"]`.
- **`MAX_PAGES_PER_ROLE` & `CRAWL_DEPTH`**: Caps the maximum number of pages and recursive depth to prevent infinite loops.

## Instructions to Run

1. **Install Dependencies**:
   Run the following commands to install the required libraries and the chromium browser binary:
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

2. **Execute Crawler**:
   ```bash
   python Crawler.py
   ```

3. **View Results**:
   The crawler will automatically generate three output files in the `results/` directory:
   - `crawl_results.txt`: A human-readable summary of the endpoints found, neatly grouped by resource type (fetch, xhr, document, script, etc.).
   - `crawl_results.csv`: A tabular report containing API payloads, responses, JWT tokens, and CSRF tokens for each endpoint.
   - `crawl_results.json`: A machine-readable JSON file containing the complete dataset for integration with downstream modules.
