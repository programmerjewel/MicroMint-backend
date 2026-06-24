# MicroMint Backend (API Server)

<p align="center"><picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://i.ibb.co.com/vv4cph99/Micromint-Logo-dark.png">
  <img alt="Your Logo" src="https://i.ibb.co.com/HDdgmqsK/Micromint-Logo-light.png" width="200">
</picture></p>



[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-blue.svg)](https://nodejs.org)
[![Express Version](https://img.shields.io/badge/express-5.2.1-green.svg)](https://expressjs.com)
[![MongoDB Driver](https://img.shields.io/badge/mongodb--driver-7.1.0-brightgreen.svg)](https://www.mongodb.com/)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

Welcome to the backend engine powering **MicroMint**—a micro-tasking and micro-earning ecosystem built to bridge digital crowdsourcing needs with micro-earners. The server manages complex authentication rules, atomic multi-role wallet deductions, specialized multi-step notifications, complex aggregations, and robust security middlewares.

---

## 🚀 Key Features

### 🔍 Advanced Aggregation & Live Query Engine
* **Dynamic Task Filters:** Server-side search, multi-axis pagination, and sorting optimized using MongoDB's Native Aggregation pipelines. Filter tasks seamlessly by category, deadline, reward margins, and open allocation status.
* **Public Platform Metrics:** Real-time generation of public homepage insights (`/public-stats`) aggregating total platform micro-workers, premium buyers, gross coin liquidity pools, and total dollar pay-outs.

### 🛡️ Secure RBAC (Role-Based Access Control)
* Strict validation routing guarding three independent privilege profiles (**Worker**, **Buyer**, **Admin**).
* **Token Lifecycle Protection:** Automatic validation matching authorization signatures. Any missing tokens throw an immediate `401 Unauthorized` block, stale or mutated tokens trigger a `400 Bad Request`, and unauthorized permission traversal issues a strict `403 Forbidden Access` alongside systematic forced client session resets.

### 📈 Multi-tier Role Workflows & Micro-Economy

* **Default Joining Matrix:** Workers auto-claim a registration bonus; Buyers auto-claim a separate buyer bonus. Drops are strictly validated to occur only once per unique identity lifecycle.
* **Asymmetric Liquidity Margins:** Buyers purchase coin bundles natively via Stripe. Earned assets are distributed to Workers through a designated withdrawal ratio, ensuring a sustainable platform revenue cut on gross cashflows.

#### ⚙️ Micro-Economy Configurations (`.env`)
The parameters driving this micro-economy are fully dynamic and can be adjusted via the following environment variables:

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `WORKER_SIGNUP_BONUS` | `10` | Number of coins granted to a Worker upon registration. |
| `BUYER_SIGNUP_BONUS` | `50` | Number of coins granted to a Buyer upon registration. |
| `DEPOSIT_COIN_RATE` | `10` | The buying rate for bundle purchases (e.g., `10` Coins = $1). |
| `WITHDRAW_COIN_RATE` | `20` | The conversion rate for Worker payouts (e.g., `20` Coins = $1). |

#### 💸 Atomic Task Ledger Operations
* **Task Creation Validation:** Dynamically verifies that a Buyer’s active wallet balance covers the total scope cost ($RequiredWorkers \times PayableAmount$). Insufficient funds immediately abort the transaction and trigger an error response.
* **Task Resolutions:**
  * **Approvals:** Atomically transfers the designated coin payload from the held escrow directly into the Worker's active balance.
  * **Rejections:** Rollbacks the transaction, returning the unspent coin allocation back to the Buyer and incrementing the remaining task capacity (`required_workers + 1`).

### 🔔 Centralized Reactive Notifications
* Custom system logging that processes context-driven message payloads across all workflow lifecycle events (Submissions ➡️ Approvals ➡️ Rejections ➡️ Admin Payout Approvals).
* Queries fetch items using clear descending time paths (`createdAt: -1`) rendered conditionally into real-time operational streams.

---

## 🛠️ Tech Stack & Dependencies

* **Runtime Environment:** Node.js (v18+ recommended)
* **Framework:** Express.js (v5.2.1)
* **Database Engine:** MongoDB Native Driver (v7.1.0) — *Built completely without Mongoose ODM for raw query execution and performance optimization.*
* **Authentication & Session Management:** JSON Web Tokens (`jsonwebtoken`), `cookie-parser`, Firebase Admin SDK (Targeted Identity validations).
* **Time & Date Manipulation:** Luxon (`luxon`) for exact server timezone tracking.
* **Environment Management:** `@dotenvx/dotenvx` for enterprise-grade secret management.

---

## 📂 Architecture & Directory Map

```text
micromint-backend/
├── index.js              # Central application entry point, routing mapping & database bindings
├── package.json          # Application configuration, script engines, and library matrix
├── README.md             # Project documentation and architectural setup guides
└── .env.example          # Template schema for environment variable configuration

```

## 📡 Core API Endpoints

### 🔓 Public & General Infrastructure
| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/public-stats` | Calculates cumulative users, buyers, active coins, and total USD volumes | Open |
| `GET` | `/homepage-live-tasks` | Fetches 3 newest open tasks featuring active vacancy slots | Open |
| `GET` | `/top-workers` | Returns top 6 platform earners sorted by coin density profiles | Open |

### 🔑 Authentication & Token Lifecycle
| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/jwt` | Generates secure HttpOnly access tokens upon login validation | Open |
| `POST` | `/logout` | Clears local active session cookies and active tokens | Open |

### 🛠️ Worker Operations
| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/tasks/available` | Fetches non-expired tasks with active allocations (`required_workers > 0`) | Worker |
| `POST` | `/submissions/add` | Inserts worker completion log proofs (sets status to `pending`) | Worker |
| `GET` | `/submissions/my-history` | Paginated repository matching active account execution logs | Worker |
| `POST` | `/withdrawals/request` | Submits payment processing form logs to Admin collections | Worker |

### 💼 Buyer Operations
| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/tasks/create` | Validates balance, deducts coin amounts, creates task logs | Buyer |
| `GET` | `/buyer/my-tasks` | Lists current buyer-owned tasks in descending date order | Buyer |
| `PATCH` | `/submissions/review/:id` | Handles approval wallet payouts or rejection slot rollbacks | Buyer |
| `POST` | `/payments/create-intent` | Stripe backend payment intent creation endpoint | Buyer |

### 👑 Admin Management
| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/admin/users` | Lists complete administrative user logs with operational flags | Admin |
| `PATCH` | `/admin/users/update-role` | Updates targeted account permissions dynamically | Admin |
| `DELETE` | `/admin/users/remove/:id` | Permanently drops a user account from database records | Admin |
| `PATCH` | `/admin/withdrawals/approve` | Processes withdrawal tokens and updates worker wallets | Admin |

---



⚙️ Local Development Installation
---------------------------------

Follow these steps to configure your local development environment:

### 1. Clone the Repository

```bash
git clone https://github.com/programmerjewel/micromint-backend.git
cd micromint-backend  
```

### 2\. Install Project Dependencies

```bash 
npm install   
```

### 3\. Setup Environment Variables

Create a `.env` file in the root directory of the backend project and configure the following variables:

```env
PORT=5000
DB_USER=your_mongodb_username
DB_PASS=your_mongodb_password
JWT_SECRET=your_super_secret_jwt_signature_key
DB_USER=micromint_admin
DB_PASS=your_mongodb_password
NODE_ENV=development
COIN_TO_DOLLAR_RATE=coin_to_dollar_rate_for_the_platform
WITHDRAW_COIN_TO_DOLLAR_RATE=coin_to_dollar_rate_for_the_platform
DEFAULT_COIN_BUYER=default_coin_after_register_to_the_platform
DEFAULT_COIN_WORKER=default_coin_after_register_to_the_platform
MIN_WITHDRAW_COINS=minimum_withdrawable_coins
DAILY_COIN_LIMIT=daily_purchase_coin_ilmit
MONTHLY_COIN_LIMIT=monthly_coin_limit
FIREBASE_SERVICE_ACCOUNT={"type":"service_account","project_id":"your_project_id","private_key":"your_private_key","client_email":"your_client_email"}
 ```

### 4\. Execute Server Engine

Run the development server using the active configurations managed via @dotenvx/dotenvx:

```bash
npm start   
```

The console will verify connection integrity by printing:

```   Server listening efficiently on port 3000   Connected to MongoDB!   ```

🔒 Security Architecture Highlights
-----------------------------------

*   **No Mongoose Strategy:** Eliminates complex schema overhead and middleware abstraction blocks by interacting directly with the native MongoDB collection engine. This ensures all state transitions remain atomic, faster, and predictable.
    
*   **Strict Access Revocation:** Implements an automated route fallback pattern. When an active verification layer fails, it intercepts the server stack, appends standard HTTP error codes (401, 400, or 403), and commands immediate cookie clearance parameters to prevent token-spoofing techniques.
    

📝 License
----------

Distributed under the **ISC License**. See package.json for details.