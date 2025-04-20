import mermaid from "mermaid"; // add Mermaid for diagrams
// Import Chart for CSRF demo
// Optional: Import OrbitControls for camera interaction if needed later
// import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';

const securityConcepts = [
	{
		id: "xss",
		title: "XSS (Cross-Site Scripting)",
		description:
			"Attacker injects malicious scripts into web pages viewed by others.",
	},
	{
		id: "csrf",
		title: "CSRF (Cross-Site Request Forgery)",
		description:
			"Tricks users into submitting unintended actions on trusted sites.",
	},
	{
		id: "sql-injection",
		title: "SQL Injection",
		description:
			"Injecting malicious SQL through user inputs to manipulate the database.",
	},
	{
		id: "authn-authz",
		title: "Authentication vs Authorization",
		description:
			"AuthN verifies who you are, AuthZ checks what you're allowed to do.",
		interactiveHTML: `
			<h4>Authentication (AuthN)</h4>
			<p>Verifies your identity by checking credentials (e.g., username & password).</p>
			<p><strong>Example:</strong> Logging in as <code>jane.doe@example.com</code> with your password.</p>
			<p><em>Limitation of AuthN only:</em> Any authenticated user—malicious or not—could attempt to access sensitive features simply by being logged in. For instance, a regular user might call admin APIs directly and gain unauthorized access if no additional checks exist.</p>

			<h4>Authorization (AuthZ)</h4>
			<p>Checks what actions or resources authenticated users are allowed to access.</p>
			<p><strong>Example:</strong> A user with role <code>guest</code> should not access <code>/admin/dashboard</code>.</p>
			<p><em>Why AuthZ is crucial in large applications:</em> Big apps often have many roles, resources, and microservices. Proper authorization enforces least privilege, prevents privilege escalation across modules, and ensures each user can only access their permitted data and actions.</p>
		`,
	},
	{
		id: "jwt",
		title: "JWT (JSON Web Token)",
		description:
			"A compact, signed token used to transmit identity and claims securely.",
		interactiveHTML: `
			<h4>Where JWTs Are Used</h4>
			<ul>
				<li>Authentication tokens in SPAs and mobile apps</li>
				<li>Authorization between microservices in distributed systems</li>
				<li>Secure information exchange (e.g., OAuth/OIDC flows)</li>
			</ul>
			<h4>Why Use JWT</h4>
			<ul>
				<li>Compact and URL-safe</li>
				<li>Self-contained: carries its own claims (no server session state)</li>
				<li>Stateless: scales easily across multiple servers</li>
			</ul>
			<h4>JWT Structure</h4>
			<pre><code>header.payload.signature</code></pre>
			<ul>
				<li><strong>Header:</strong> Algorithm & token type (Base64Url JSON)</li>
				<li><strong>Payload:</strong> Claims like user ID, roles</li>
				<li><strong>Signature:</strong> Verifies integrity</li>
			</ul>
			<h4>Pros</h4>
			<ul>
				<li>No need for server-side session store</li>
				<li>Easily scalable and CORS-friendly</li>
				<li>Supports rich, typed claims</li>
			</ul>
			<h4>Cons</h4>
			<ul>
				<li>Difficult to revoke before expiry</li>
				<li>Larger token size than opaque tokens</li>
				<li>Risk if stolen: bearer tokens grant access</li>
				<li>May expose data if not encrypted</li>
			</ul>
			<h4>Developer Guidelines</h4>
			<h5>Do:</h5>
			<ul>
				<li>Use strong signing algorithms (e.g., RS256) and manage keys securely.</li>
				<li>Set short token lifetimes and implement secure refresh flows.</li>
				<li>Validate signature and claims (issuer, audience, expiration) on every request.</li>
			</ul>
			<h5>Don't:</h5>
			<ul>
				<li>Store JWTs in localStorage for sensitive apps (use HttpOnly cookies).</li>
				<li>Skip verifying token signature or claims server-side.</li>
				<li>Embed sensitive PII in unencrypted JWT payloads.</li>
			</ul>
		`,
	},
	{
		id: "oauth2",
		title: "OAuth2",
		description:
			"A protocol that allows third-party apps to access user data without sharing credentials.",
	},
	{
		id: "open-redirects",
		title: "Open Redirects",
		description:
			"Vulnerability where attackers can abuse redirect links on trusted domains to send users to malicious sites.",
		interactiveHTML: `
			<h4>Open Redirect Flow</h4>
			<pre class="mermaid">
flowchart LR
    A[User clicks link on trusted.com] --> B[trusted.com/redirect?url=target]
    B --> C[Server redirects to target URL]
    C --> D[User lands on the destination site]
			</pre>

			<h4>Attack Scenario</h4>
			<p>An attacker sends: <code>https://trusted.com/redirect?url=https://malicious.com</code> via email or social media. The user sees the <em>trusted.com</em> domain and clicks, but ends up on <strong>malicious.com</strong>.</p>

			<h4>Impact & Usage by Attackers</h4>
			<ul>
				<li>Phishing: display fake login pages under a trusted domain to harvest credentials.</li>
				<li>Malware distribution: host malicious downloads without raising suspicion.</li>
				<li>Filter bypass: trusted domains often bypass email and web filters.</li>
			</ul>
		`,
	},
	{
		id: "session-hijacking",
		title: "Session Hijacking",
		description:
			"Stealing a user's session ID (often from a cookie) to impersonate them.",
		interactiveHTML: `
  	<h4>Session Hijacking Flow</h4>
  	<pre class="mermaid">
flowchart LR
    A[User logs in] --> B[Server sets session cookie]
    B --> C[Attacker steals cookie via XSS/sniffing]
    C --> D[Attacker sends cookie with requests]
    D --> E[Server accepts and impersonates user]
  	</pre>

  	<h4>Attack Methods</h4>
  	<ul>
  	  <li>XSS: malicious script reads <code>document.cookie</code>.</li>
  	  <li>Network sniffing: HTTP traffic exposes cookies when not encrypted.</li>
  	  <li>Malware: system exploits extract session cookies.</li>
  	  <li>Predictable session IDs: brute-forcing weak identifiers.</li>
  	</ul>

  	<h4>Developer Guidelines</h4>
  	<h5>Do:</h5>
  	<ul>
  	  <li>Use <code>Secure</code>, <code>HttpOnly</code>, and <code>SameSite</code> flags on cookies.</li>
  	  <li>Rotate session IDs after login and periodically.</li>
  	  <li>Implement short timeouts and re-authentication for sensitive actions.</li>
  	  <li>Monitor and validate session context (IP, user-agent).</li>
  	</ul>
  	<h5>Don't:</h5>
  	<ul>
  	  <li>Expose session tokens in JavaScript-accessible storage unnecessarily.</li>
  	  <li>Use sequential or predictable session identifiers.</li>
  	  <li>Allow excessively long session lifetimes without renewal.</li>
  	</ul>
	`,
	},
	{
		id: "brute-force",
		title: "Brute Force Attack",
		description:
			"Guessing passwords or tokens by systematically trying all possibilities.",
	},
	{
		id: "rate-limiting",
		title: "Rate Limiting",
		description:
			"Prevents abuse by limiting how often a user or IP can hit an endpoint.",
	},
	{
		id: "password-hashing",
		title: "Password Hashing",
		description:
			"Storing passwords securely using one-way functions like bcrypt or Argon2.",
		interactiveHTML: `
		  <h4>Why Password Hashing is Needed</h4>
		  <p>Storing passwords in plain text is extremely risky. If a database is breached, all user credentials would be immediately exposed, leading to widespread account compromises.</p>

		  <h4>What Password Hashing Prevents</h4>
		  <p>Password hashing prevents attackers from reading passwords directly from a stolen database. Even if an attacker gains access to the hashed passwords, they cannot easily reverse the hash to get the original password, especially when strong, slow hashing algorithms and unique salts are used. This significantly limits the damage of a data breach.</p>

		  <h4>When to Hash Passwords</h4>
		  <p>Passwords should be hashed as soon as they are received from the user, typically during account creation or password change operations. The hashed password, along with a unique salt, should be stored in the database instead of the plain-text password. When a user attempts to log in, the entered password should be hashed with the stored salt and compared to the stored hash.</p>

		  <h4>Best Practices</h4>
		  <ul>
		    <li>Use slow, adaptive algorithms (bcrypt, Argon2) with high work factors.</li>
		    <li>Generate a unique salt for each password.</li>
		    <li>Optionally add a server-side pepper stored outside the database.</li>
		  </ul>

		  <h4>Developer Guidelines</h4>
		  <h5>Do:</h5>
		  <ul>
		    <li>Leverage well-maintained libraries (bcrypt.js, argon2).</li>
		    <li>Enforce strong password policies (length, complexity).</li>
		    <li>Rotate hashing parameters (work factor) periodically.</li>
		  </ul>
		  <h5>Don't:</h5>
		  <ul>
		    <li>Use fast hashes (MD5, SHA1) for password storage.</li>
		    <li>Hard-code salts or peppers in client-side code.</li>
		    <li>Reuse salts across multiple users.</li>
		  </ul>
		`,
	},
	{
		id: "salting",
		title: "Salting",
		description:
			"Adds randomness to passwords before hashing to prevent rainbow table attacks.",
		interactiveHTML: `
		  <h4>What is Salting?</h4>
		  <p>A salt is a unique, random value added to each password <em>before</em> hashing. It prevents attackers from using precomputed rainbow tables to crack multiple passwords at once.</p>

		  <h4>Why Salting Works</h4>
		  <p>Even if two users have the same password (e.g., "password123"), their unique salts result in completely different stored hashes. This forces attackers to compute hashes individually for each user, making rainbow table attacks infeasible.</p>
		  <p>Hash Storage: <code>hash(salt + password)</code> alongside the unique <code>salt</code>.</p>

		  <h4>Code Example (Reusing bcrypt logic)</h4>
		  <pre><code class="language-javascript">
async function hashPassword(plainPassword) {
  // Generate a unique, random salt for *this* user
  const salt = await bcrypt.genSalt(saltRounds); 
  // Hash the password combined with the unique salt
  const hash = await bcrypt.hash(plainPassword, salt);
  // Store BOTH the salt and the hash in the database
  return { salt, hash }; 
}

async function checkPassword(plainPassword, storedHash) {
  // bcrypt.compare automatically extracts the salt from storedHash
  return await bcrypt.compare(plainPassword, storedHash);
}
		  </code></pre>

		  <h4>Developer Guidelines</h4>
		  <h5>Do:</h5>
		  <ul>
		    <li>Generate a cryptographically secure, unique salt for every password.</li>
		    <li>Store the salt alongside the hash in the database (e.g., in the same column or a separate one).</li>
		    <li>Use library functions (like bcrypt's) that handle salt generation and storage implicitly.</li>
		  </ul>
		  <h5>Don't:</h5>
		  <ul>
		    <li>Use a static, hardcoded salt for all users (defeats the purpose).</li>
		    <li>Reuse salts across different users.</li>
		    <li>Use predictable values (like username or email) as salts.</li>
		  </ul>
		`,
	},
	{
		id: "tls",
		title: "TLS (Transport Layer Security)",
		description:
			"Encrypts traffic between client (browser) and server to prevent eavesdropping. (Successor to SSL)",
		interactiveHTML: `<p>Provides:</p><ul><li><b>Encryption:</b> Prevents others from reading the data (padlock icon).</li><li><b>Authentication:</b> Verifies the server is who it claims to be (using certificates).</li><li><b>Integrity:</b> Ensures data hasn't been tampered with in transit.</li></ul><p>Uses a handshake process to establish a secure connection.</p>`,
	},
	{
		id: "hsts",
		title: "HSTS (HTTP Strict Transport Security)",
		description:
			"Forces browsers to only connect over HTTPS, even if the user types HTTP.",
		interactiveHTML: `
		  <h4>What is HSTS?</h4>
		  <p>HTTP Strict Transport Security (HSTS) is a web security policy mechanism that helps to protect websites against man-in-the-middle attacks, particularly protocol downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol.</p>

		  <h4>How HSTS Works</h4>
		  <p>When a browser connects to a website over HTTPS that has HSTS enabled, the server includes a <code>Strict-Transport-Security</code> header in the response. This header tells the browser to automatically convert any future attempts to access the site using HTTP to HTTPS for a specified period (<code>max-age</code>). This prevents attackers from tricking users into connecting over insecure HTTP, even if they explicitly type <code>http://</code>.</p>

		  <pre><code class="language-http">
Strict-Transport-Security: max-age=31536000; includeSubDomains
		  </code></pre>

		  <ul>
		    <li><code>max-age</code>: The time in seconds that the browser should remember the HSTS setting. A year is a common value (31536000 seconds).</li>
		    <li><code>includeSubDomains</code>: An optional directive that applies the HSTS policy to all subdomains of the site as well.</li>
		  </ul>

		  <h4>Why HSTS is Important</h4>
		  <p>HSTS is a crucial layer of defense against attacks that rely on downgrading a user's connection from secure HTTPS to insecure HTTP. Without HSTS, an attacker could intercept a user's initial HTTP request and redirect them to a malicious site or capture sensitive information transmitted over the insecure connection. HSTS ensures that once a browser has seen the header, it will only communicate with the site over HTTPS, even on subsequent visits or if the user tries to access the site via an HTTP link.</p>

		  <h4>Developer Guidelines</h4>
		  <h5>Do:</h5>
		  <ul>
		    <li>Implement HSTS on all websites that handle sensitive information or require secure connections.</li>
		    <li>Set a sufficiently long <code>max-age</code> to ensure users are protected for an extended period.</li>
		    <li>Consider including the <code>includeSubDomains</code> directive if you want the policy to apply to your subdomains.</li>
		    <li>Submit your domain to the HSTS preload list to hardcode the policy in browsers.</li>
		  </ul>
		  <h5>Don't:</h5>
		  <ul>
		    <li>Implement HSTS without ensuring your entire site and all subdomains are fully accessible over HTTPS first. Otherwise, you risk making your site inaccessible to users.</li>		    <li>Use a very short <code>max-age</code>, as this reduces the effectiveness of the policy.</li>
		  </ul>
		`,
	},
	{
		id: "security-headers",
		title: "Security Headers",
		description:
			"HTTP headers like Content-Security-Policy and X-Frame-Options protect web apps.",
		interactiveHTML: `
		  <h4>Common Security Headers</h4>
		  <p>Security headers are HTTP response headers that instruct browsers to enforce security policies. Properly configured, they help protect against XSS, clickjacking, MIME sniffing, and other attacks.</p>
		  <ul>
		    <li><strong>Content-Security-Policy (CSP):</strong> Restricts resource loading (scripts, images, styles) to trusted sources. Prevents XSS.</li>
		    <li><strong>X-Frame-Options:</strong> Controls whether the site can be embedded in frames/iframes. Protects against clickjacking (<code>DENY</code> or <code>SAMEORIGIN</code>).</li>
		    <li><strong>X-Content-Type-Options:</strong> Prevents MIME sniffing by enforcing declared <code>Content-Type</code> (<code>nosniff</code>).</li>
		    <li><strong>Referrer-Policy:</strong> Limits the information sent in the Referer header. Enhances privacy.</li>
		    <li><strong>Permissions-Policy:</strong> Specifies which browser features (camera, microphone, geolocation) are allowed.</li>
		  </ul>

		  <h4>Why They Matter</h4>
		  <ul>
		    <li><strong>CSP:</strong> Blocks unauthorized scripts and mixed content.</li>
		    <li><strong>Frame Options:</strong> Prevents clickjacking attacks that trick users into clicking hidden buttons.</li>
		    <li><strong>MIME Sniffing:</strong> Forces browsers to honor declared content types.</li>
		    <li><strong>Referrer-Policy:</strong> Protects user privacy by controlling what URL data is exposed.</li>
		    <li><strong>Permissions-Policy:</strong> Reduces risk by limiting powerful APIs.</li>
		  </ul>

		  <h4>Developer Guidelines</h4>
		  <h5>Do:</h5>
		  <ul>
		    <li>Define a strict CSP tailored to your application content and domains.</li>
		    <li>Set <code>X-Frame-Options</code> to <code>SAMEORIGIN</code> or <code>DENY</code>, as needed.</li>
		    <li>Enable <code>X-Content-Type-Options: nosniff</code> to prevent MIME sniffing.</li>
		    <li>Choose a privacy-friendly Referrer Policy, e.g., <code>strict-origin-when-cross-origin</code>.</li>
		    <li>Lock down Permissions-Policy to only the features you use.</li>
		  </ul>
		  <h5>Don't:</h5>
		  <ul>
		    <li>Rely solely on CSP for XSS prevention—combine with proper input validation and output encoding.</li>
		    <li>Use overly permissive wildcard directives like <code>*</code> in CSP without necessity.</li>
		    <li>Forget to update headers when your application's resource requirements change.</li>
		  </ul>
		`,
	},
	{
		id: "cors",
		title: "CORS (Cross-Origin Resource Sharing)",
		description:
			"Controls which domains can access your APIs from the browser.",
		interactiveHTML: `
		  <h4>Why CORS Matters</h4>
		  <p>The browser's <strong>Same-Origin Policy</strong> blocks cross-origin requests by default to protect users. CORS allows servers to specify when such requests are safe.</p>

		  <h4>CORS Request Flow</h4>
		  <pre class="mermaid">
 sequenceDiagram
     Browser->>Server: Preflight OPTIONS (Origin, Access-Control-Request-Method, Access-Control-Request-Headers)
     Server-->>Browser: 200 OK (Access-Control-Allow-Origin, Access-Control-Allow-Methods, Access-Control-Allow-Headers, [Access-Control-Allow-Credentials])
     Browser->>Server: Actual Request (e.g., POST /data with Origin)
     Server-->>Browser: 200 OK (Access-Control-Allow-Origin, [Access-Control-Allow-Credentials])
      </pre>

		  <h4>Required Headers</h4>
		  <h5>Browser Sends:</h5>
		  <ul>
		    <li><code>Origin</code>: Requesting origin (mandatory on all cross-origin requests).</li>
		    <li><code>Access-Control-Request-Method</code>: Method for actual request (in preflight).</li>
		    <li><code>Access-Control-Request-Headers</code>: Custom headers (in preflight if any).</li>
		  </ul>

		  <h5>Server Responds:</h5>
		  <ul>
		    <li><code>Access-Control-Allow-Origin</code>: Allowed origin(s) (<code>*</code> if no credentials).</li>
		    <li><code>Access-Control-Allow-Methods</code>: Permitted HTTP methods (in preflight).</li>
		    <li><code>Access-Control-Allow-Headers</code>: Permitted custom headers (in preflight).</li>
		    <li><code>Access-Control-Allow-Credentials</code>: Whether to allow cookies/credentials (if needed).</li>
		  </ul>

		  <h4>Developer Guidelines</h4>
		  <h5>Do:</h5>
		  <ul>
		    <li>Use explicit origins instead of <code>*</code> when allowing credentials.</li>
		    <li>Allow only the HTTP methods and headers your API requires.</li>
		    <li>Properly handle OPTIONS preflight requests on the server.</li>
		  </ul>
		  <h5>Don't:</h5>
		  <ul>
		    <li>Combine <code>*</code> with credentials.</li>
		    <li>Expose sensitive data via overly permissive CORS.</li>
		    <li>Ignore browser CORS errors—they indicate misconfiguration.</li>
		  </ul>
		`,
	},
	{
		id: "input-validation",
		title: "Input Validation",
		description:
			"Ensures only valid data is accepted to prevent injection and logic errors.",
		interactiveHTML: `
		  <h4>Input Validation Demo</h4>
		  <div style="display:flex; gap:2rem; flex-wrap:wrap; margin-bottom:1rem;">
		    <div>
		      <h5>Email Format</h5>
		      <input id="email-input" placeholder="user@example.com" value="<script>alert('XSS')</script>@example.com" style="padding:0.5rem; border:1px solid #ccc; width:200px;" />
		      <p id="email-result"></p>
		    </div>
		    <div>
		      <h5>Number Range (1–100)</h5>
		      <input id="num-input" type="number" placeholder="Enter number" value="150" style="padding:0.5rem; border:1px solid #ccc; width:100px;" />
		      <p id="num-result"></p>
		    </div>
		  </div>
		  <h4>Why It Matters</h4>
		  <p>Broken or malicious inputs can lead to XSS, logic errors, or security vulnerabilities if not properly validated or sanitized.</p>
		`,
	},
	{
		id: "least-privilege",
		title: "Principle of Least Privilege",
		description:
			"Give users and systems the minimum access needed to function.",
		interactiveHTML: `
		  <h4>What Is Least Privilege?</h4>
		  <p>The Principle of Least Privilege means giving users, systems, and processes only the permissions they absolutely need to perform their tasks—and no more.</p>

		  <h4>Examples</h4>
		  <ul>
		    <li><strong>Users:</strong> A regular user account shouldn't have admin rights. An editor should only manage content, not server settings.</li>
		    <li><strong>Services:</strong> Run web servers under a dedicated low-privilege account, not <code>root</code>.</li>
		    <li><strong>API Keys:</strong> Issue keys with access limited to specific endpoints or data scopes.</li>
		    <li><strong>Containers & VMs:</strong> Limit container capabilities and use separate namespaces.</li>
		  </ul>

		  <h4>Benefits</h4>
		  <ul>
		    <li>Minimizes attack surface—compromised accounts have limited power.</li>
		    <li>Prevents lateral movement—limits what an attacker can access next.</li>
		    <li>Improves auditability—easy to track and review permissions.</li>
		    <li>Supports defense in depth—combined with other controls reduces risk.</li>
		  </ul>

		  <h4>Developer Guidelines</h4>
		  <h5>Do:</h5>
		  <ul>
		    <li>Regularly review and remove unused permissions.</li>
		    <li>Use role-based access control (RBAC) or attribute-based policies.</li>
		    <li>Automate permission assignments and rotations.</li>
		    <li>Grant temporary elevated rights only when needed (just-in-time access).</li>
		  </ul>
		  <h5>Don't:</h5>
		  <ul>
		    <li>Use blanket admin or root permissions for routine tasks.</li>
		    <li>Ignore or postpone permission revocation for departing users/services.</li>
		    <li>Hard-code elevated credentials in code or scripts.</li>
		  </ul>
		`,
	},
	{
		id: "secrets-management",
		title: "Secrets Management",
		description:
			"Store and access API keys or credentials securely, not in code or env files.",
		interactiveHTML: `
		  <h4>Why Not Commit Secrets?</h4>
		  <p>Studies show over <strong>50%</strong> of developers accidentally commit secrets to repositories, often via unignored <code>.env</code> files, risking data exposure.</p>

		  <h4>Common Mistake</h4>
		  <pre><code class="bad">// Accidentally added to source control via .env
API_KEY=sk_live_veryRealSecretKey...
DB_PASSWORD=SuperSecret123
</code></pre>

		  <h4>Secure Options</h4>
		  <ul>
		    <li><strong>Environment Variables:</strong> Keep <code>.env</code> local and add it to <code>.gitignore</code>.</li>
		    <li><strong>Encrypted Configs:</strong> Use encrypted files with strict file-system permissions.</li>
		    <li><strong>Secrets Stores:</strong> Use HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager for centralized management, auditing, and rotation.</li>
		  </ul>

		  <h4>Developer Guidelines</h4>
		  <h5>Do:</h5>
		  <ul>
		    <li>Add <code>.env</code> to <code>.gitignore</code> and never commit it.</li>
		    <li>Integrate secret scanners (e.g., git-secrets, TruffleHog) in pre-commit or CI.</li>
		    <li>Rotate secrets immediately upon any exposure.</li>
		    <li>Grant minimal permissions and rotate periodically.</li>
		  </ul>
		  <h5>Don't:</h5>
		  <ul>
		    <li>Hard-code credentials directly in code or client assets.</li>
		    <li>Share <code>.env</code> via email, chat, or public channels.</li>
		    <li>Assume files won't be committed without automated checks.</li>
		  </ul>
		`,
	},
	{
		id: "security-auditing",
		title: "Security Auditing",
		description:
			"Regular checks on code, infra, and dependencies to spot vulnerabilities.",
		interactiveHTML: `
		  <h4>What is Security Auditing?</h4>
		  <p>Security auditing is the ongoing process of evaluating code, infrastructure, and dependencies to uncover vulnerabilities before attackers can exploit them.</p>

		  <h4>Key Practices</h4>
		  <ul>
		    <li><strong>Code Reviews:</strong> Peer reviews to catch logic flaws and insecure patterns early.</li>
		    <li><strong>Static Analysis (SAST):</strong> Automated tools (e.g., SonarQube, ESLint security plugins) analyze source code for vulnerabilities.</li>
		    <li><strong>Dynamic Analysis (DAST):</strong> Runtime scanners (e.g., OWASP ZAP, Burp Suite) test the live application for security gaps.</li>
		    <li><strong>Dependency Scanning:</strong> Tools like npm audit, Snyk, or Dependabot to identify and update vulnerable libraries.</li>
		    <li><strong>Penetration Testing:</strong> Manual or automated simulated attacks to verify defenses and find complex issues.</li>
		    <li><strong>Infrastructure Scans:</strong> Assess server/container configurations and network settings (e.g., Nessus, OpenSCAP).</li>
		  </ul>

		  <h4>Why Continuous Auditing?</h4>
		  <p>Integrating security checks into your development lifecycle ensures vulnerabilities are caught early and reduces risk of production incidents.</p>

		  <h4>Developer Guidelines</h4>
		  <h5>Do:</h5>
		  <ul>
		    <li>Embed SAST and dependency scans into pre-commit hooks and CI/CD pipelines.</li>
		    <li>Hold regular security-focused code review sessions.</li>
		    <li>Schedule DAST and penetration tests before major releases.</li>
		    <li>Track and triage findings by severity, addressing critical issues first.</li>
		  </ul>
		  <h5>Don't:</h5>
		  <ul>
		    <li>Treat auditing as a one-time task—make it a continuous process.</li>
		    <li>Ignore low-severity issues—small vulnerabilities can compound.</li>
		    <li>Overload teams with redundant scans—define clear ownership and response workflows.</li>
		  </ul>
		`,
	},
];

// DOM Elements
const conceptListUl = document.querySelector("#concept-list ul");
const conceptTitleH2 = document.getElementById("concept-title");
const conceptDescriptionP = document.getElementById("concept-description");
const interactiveAreaDiv = document.getElementById("interactive-area");

let currentConceptId = null;

// --- Populate Concept List ---
function populateConceptList() {
	for (const concept of securityConcepts) {
		const li = document.createElement("li");
		const button = document.createElement("button");
		button.textContent = concept.title;
		button.dataset.conceptId = concept.id; // Store id for lookup
		button.addEventListener("click", handleConceptClick);
		li.appendChild(button);
		conceptListUl.appendChild(li);
	}
}

// --- Handle Concept Selection ---
function handleConceptClick(event) {
	const conceptId = event.target.dataset.conceptId;
	if (conceptId === currentConceptId) return; // Don't reload if already selected

	currentConceptId = conceptId;
	const concept = securityConcepts.find((c) => c.id === conceptId);

	if (concept) {
		conceptTitleH2.textContent = concept.title;
		conceptDescriptionP.textContent = concept.description;
		interactiveAreaDiv.innerHTML =
			concept.interactiveHTML ||
			"<p>No interactive demo for this concept yet.</p>";

		// Update active button style
		const buttons = document.querySelectorAll("#concept-list button");
		for (const btn of buttons) {
			btn.classList.toggle("active", btn.dataset.conceptId === conceptId);
		}

		// Sidebar close on mobile
		document.getElementById("app")?.classList.remove("menu-open");

		// three.js update
		if (conceptId === "xss") setupXssDemo();
		if (conceptId === "csrf") setupCsrfDemo();
		if (conceptId === "sql-injection") setupSqlInjectionDemo();
		if (conceptId === "brute-force") setupBruteForceDemo();
		if (conceptId === "rate-limiting") setupRateLimitingDemo();
		if (conceptId === "oauth2") setupOauth2Demo();
		if (conceptId === "input-validation") setupInputValidationDemo();
		// Render Mermaid diagrams for CORS and selected concepts
		if (["open-redirects", "session-hijacking", "cors"].includes(conceptId))
			mermaid.run();
	}
}

// --- Function to set up interactive XSS demo ---
function setupXssDemo() {
	interactiveAreaDiv.innerHTML = `
		<div style="background:#fff; color:#000; padding:1rem; border:1px solid #ccc; border-radius:6px;">
			<h3 style="margin-top:0;">XSS Interactive Demo</h3>
			<p>Cross-Site Scripting (XSS) lets attackers inject scripts into webpages. Modify the default payload below or enter your own code, then click <strong>Render</strong> to compare unsafe execution vs sanitized output.</p>
			<h4 style="margin:0.75rem 0 0.25rem;">How XSS Is Performed:</h4>
			<ul style="margin:0 0 0.75rem 1.25rem;">
				<li>Injecting unsanitized user input into HTML content or attributes (e.g., via forms, URLs, comments)</li>
				<li>Inserting <code>&lt;script&gt;</code> tags, event handlers (<code>onerror</code>, <code>onclick</code>), or malformed attributes</li>
				<li>Exploiting vulnerabilities in input validation or missing output encoding</li>
			</ul>
			<h4 style="margin:0.75rem 0 0.25rem;">What Attackers Can Do:</h4>
			<ul style="margin:0 0 1rem 1.25rem;">
				<li>Steal session cookies or authentication tokens (<code>document.cookie</code>)</li>
				<li>Hijack user sessions, deface pages, or modify content</li>
				<li>Redirect users, perform unauthorized actions, or launch phishing attacks</li>
				<li>Deliver malware or keyloggers directly in the browser</li>
			</ul>
			<label for="xss-input" style="display:block; margin:0.5rem 0 0.25rem;">Enter HTML or script:</label>
			<textarea id="xss-input" rows="3" style="width:100%; font-family: monospace; font-size:0.9rem; padding:0.5rem; border:1px solid #ccc;" placeholder="Enter HTML or script here"></textarea>
			<button id="xss-render" style="margin:0.5rem 0; padding:0.5rem 1rem;">Render</button>
			<div style="display:flex; gap:1rem; margin-top:1rem;">
				<div style="flex:1;">
					<h4 style="margin:0 0 0.5rem 0; color:#c00;">Unsafe Render</h4>
					<div id="xss-unsafe" style="border:1px solid #c00; background:#fee; padding:1rem; min-height:50px;"></div>
				</div>
				<div style="flex:1;">
					<h4 style="margin:0 0 0.5rem 0; color:#060;">Sanitized Render</h4>
					<div id="xss-safe" style="border:1px solid #060; background:#efe; padding:1rem; min-height:50px; white-space:pre-wrap; font-family: monospace;"></div>
				</div>
			</div>
		</div>
	`;
	// Prefill with an image-based XSS payload to show an in-page effect
	const textarea = document.getElementById("xss-input");
	textarea.value =
		'<img src="invalid.jpg" onerror="this.outerHTML=\'<strong style=&quot;color:red&quot;>XSS executed!</strong>\'">';
	const renderBtn = document.getElementById("xss-render");
	renderBtn.addEventListener("click", () => {
		const value = document.getElementById("xss-input").value;
		const unsafeDiv = document.getElementById("xss-unsafe");
		const safeDiv = document.getElementById("xss-safe");
		// Unsafe: directly set innerHTML
		unsafeDiv.innerHTML = value;
		// Safe: escape by textContent
		safeDiv.textContent = value;
	});
}

// --- Function to set up CSRF demo ---
function setupCsrfDemo() {
	interactiveAreaDiv.innerHTML = `
		<div style="display:flex; gap:2rem; max-width:800px;">
			<div style="flex:1;">
				<h4>Legitimate Form (includes token)</h4>
				<p style="font-size:0.9rem; color:#888;">This form is on your bank's official site and includes a hidden CSRF token tied to your session. The server verifies this token on each request and will reject any request with an incorrect or missing token.</p>
				<p style="font-size:0.9rem; color:#888;">Form submits to: <code>https://bank.example.com/transfer</code> (same origin as your bank, so cookies are sent automatically)</p>
				<form id="bank-form" action="https://bank.example.com/transfer" method="POST">
					<input type="hidden" id="csrf-hidden" value="abc123" />
					<label>To Account: <input id="legit-to" type="text" value="friendAcc" /></label><br/>
					<label>Amount: <input id="legit-amt" type="number" value="100" /></label><br/>
					<button type="button" id="legit-submit">Send</button>
				</form>
			</div>
			<div style="flex:1;">
				<h4>Malicious Form (no token)</h4>
				<p style="font-size:0.9rem; color:#888;">On a phishing website controlled by an attacker, a form submits to your bank's transfer endpoint but omits the CSRF token. Because you are logged in, the browser automatically includes your bank's session cookies with this request, so without server-side token validation the attacker could transfer funds without your knowledge.</p>
				<p style="font-size:0.9rem; color:#888;">Although hosted on <code>https://evil-phish.com</code>, this form also submits to: <code>https://bank.example.com/transfer</code>, so the browser still sends your bank cookies.</p>
				<form id="mal-form" action="https://bank.example.com/transfer" method="POST">
					<label>To Account: <input id="mal-to" type="text" value="attackerAcc" /></label><br/>
					<label>Amount: <input id="mal-amt" type="number" value="1000" /></label><br/>
					<button type="button" id="mal-submit">Send</button>
				</form>
			</div>
		</div>
		<div style="margin-top:1rem;">
			<h4>Server Response:</h4>
			<pre id="csrf-server-log" style="background:#f0f0f0;padding:1rem;min-height:50px;"></pre>
		</div>
		<h4>Why CSRF Token?</h4>
		<p>Browsers automatically attach cookies (including session/authentication cookies) for a domain on any request, even if the request originates from another site. A CSRF token is a secret, user-specific value embedded in the legitimate site and checked server-side to ensure the request truly came from your application.</p>
		<p>As an additional mitigation, setting cookies with the <code>SameSite</code> attribute (e.g., <code>SameSite=Strict</code> or <code>SameSite=Lax</code>) can prevent them from being sent on cross-site requests.</p>
		<h4>Best Practices:</h4>
		<ul>
			<li>Generate a unique token per user session.</li>
			<li>Include the token in hidden form fields or custom headers.</li>
			<li>Validate the token server-side on each request.</li>
			<li>Rotate tokens when users log out or periodically.</li>
		</ul>
	`;
	function handleCsrfSubmit(isLegit) {
		const token = isLegit
			? document.getElementById("csrf-hidden").value
			: undefined;
		const to = isLegit
			? document.getElementById("legit-to").value
			: document.getElementById("mal-to").value;
		const amt = isLegit
			? document.getElementById("legit-amt").value
			: document.getElementById("mal-amt").value;
		const logEl = document.getElementById("csrf-server-log");
		if (token === "abc123") {
			logEl.style.color = "#6f6";
			logEl.textContent = `Success! Transferred $${amt} to ${to}`;
		} else {
			logEl.style.color = "#f66";
			logEl.textContent = "Blocked! Missing or invalid CSRF token.";
		}
	}
	document
		.getElementById("legit-submit")
		.addEventListener("click", () => handleCsrfSubmit(true));
	document
		.getElementById("mal-submit")
		.addEventListener("click", () => handleCsrfSubmit(false));
}

// --- Function to set up SQL Injection demo ---
function setupSqlInjectionDemo() {
	// Show detailed explanation and developer guidelines for SQL Injection
	interactiveAreaDiv.innerHTML = `
		<div style="max-width:600px; padding:0.5rem; background:#f9f9f9; border:1px solid #ccc; border-radius:6px; margin-bottom:1rem;">
			<h4>How SQL Injection Works:</h4>
			<ul>
				<li>An attacker injects SQL syntax by including special characters like <code>'</code>.</li>
				<li>Using <code>--</code> comments out the rest of the WHERE clause (e.g., the password check).</li>
				<li>Example: <code>SELECT * FROM users WHERE username = 'admin' --' AND password = 'irrelevant';</code> becomes <code>SELECT * FROM users WHERE username = 'admin'</code>.</li>
				<li>This bypasses authentication and grants unauthorized access.</li>
			</ul>
			<p>The prefilled malicious payload demonstrates this bypass.</p>
		</div>
		<div style="display:flex; flex-direction:column; gap:0.5rem;">
			<label>Username: <input id="sql-user" type="text" value="admin' --"></label>
			<label>Password: <input id="sql-pass" type="text" value="irrelevant"></label>
			<button id="sql-run" style="align-self:start;">Run Demo</button>
			<h4>Unsafe Query & Result</h4>
			<pre id="sql-unsafe" style="background:#2a0000; color:#f66; padding:1rem;"></pre>
			<h4>Safe (Parameterized) Query & Result</h4>
			<pre id="sql-safe" style="background:#002a00; color:#6f6; padding:1rem;"></pre>
		</div>
		<div style="margin-top:1rem; padding:0.5rem; background:#eef; border:1px solid #aac; border-radius:6px;">
			<h4>Developer Guidelines</h4>
			<h5>Do:</h5>
			<ul>
				<li>Use parameterized queries or prepared statements.</li>
				<li>Validate and sanitize all user inputs.</li>
				<li>Use ORM frameworks that handle escaping automatically.</li>
			</ul>
			<h5>Don't:</h5>
			<ul>
				<li>Concatenate user input directly into SQL queries.</li>
				<li>Rely solely on client-side validation.</li>
				<li>Trust any user-supplied data without server-side verification.</li>
			</ul>
		</div>
	`;
	document.getElementById("sql-run").addEventListener("click", () => {
		const user = document.getElementById("sql-user").value;
		const pass = document.getElementById("sql-pass").value;
		// Construct unsafe SQL query
		const unsafeQuery = `SELECT * FROM users WHERE username = '${user}' AND password = '${pass}';`;
		// Simulate result of unsafe query
		let unsafeResult;
		if (user.includes("--")) {
			unsafeResult = "Result: Logged in as admin (SQL Injection succeeded!)";
		} else if (user === "admin" && pass === "password") {
			unsafeResult = "Result: Logged in as admin (valid credentials)";
		} else {
			unsafeResult = "Result: Login failed";
		}
		// Construct safe parameterized query
		const safeQuery = `PreparedStmt: SELECT * FROM users WHERE username = ? AND password = ?;
Parameters: [ '${user}', '${pass}' ]`;
		// Simulate result of safe query
		let safeResult;
		if (user === "admin" && pass === "password") {
			safeResult = "Result: Logged in as admin (valid credentials)";
		} else {
			safeResult = "Result: Login failed";
		}
		document.getElementById("sql-unsafe").textContent =
			`${unsafeQuery}\n${unsafeResult}`;
		document.getElementById("sql-safe").textContent =
			`${safeQuery}\n${safeResult}`;
	});
}

// --- Function to set up Brute Force Attack demo ---
function setupBruteForceDemo() {
	interactiveAreaDiv.innerHTML = `
		<div style="max-width:600px; margin-bottom:1rem;">
			<h4>What Is a Brute Force Attack?</h4>
			<p>A brute force attack systematically tries all possible passwords or tokens until the correct one is found, risking unauthorized access and lockouts.</p>
			<p><strong>Impact:</strong> Account compromise, resource exhaustion, data breaches.</p>
		</div>
		<div style="display:flex; flex-direction:column; gap:0.5rem; max-width:400px;">
			<input id="bf-guess" type="text" placeholder="Enter guess" style="padding:0.5rem; font-family: monospace;" />
			<button id="bf-submit" style="align-self:start;">Submit Guess</button>
			<p>Attempts: <span id="bf-count">0</span></p>
			<p id="bf-message" style="color:#f66;"></p>
		</div>
		<h4>Developer Guidelines</h4>
		<h5>Do:</h5>
		<ul>
			<li>Implement rate limiting or account lockouts after several failures.</li>
			<li>Use CAPTCHAs or multi-factor authentication to block automation.</li>
			<li>Enforce strong password complexity and short lockout durations.</li>
		</ul>
		<h5>Don't:</h5>
		<ul>
			<li>Allow unlimited login attempts.</li>
			<li>Reveal detailed errors that help attackers enumerate accounts.</li>
			<li>Rely solely on client-side validation.</li>
		</ul>
	`;
	mermaid.run();
	const target = "secret123";
	let attempts = 0;
	const maxAttempts = 5;
	const countEl = document.getElementById("bf-count");
	const msgEl = document.getElementById("bf-message");
	const input = document.getElementById("bf-guess");
	document.getElementById("bf-submit").addEventListener("click", () => {
		if (attempts >= maxAttempts) {
			msgEl.textContent = "Too many attempts! Try again later.";
			return;
		}
		attempts++;
		countEl.textContent = attempts;
		if (input.value === target) {
			msgEl.style.color = "#6f6";
			msgEl.textContent = "Success! You guessed correctly.";
		} else {
			msgEl.style.color = "#f66";
			msgEl.textContent = "Incorrect guess.";
		}
		if (attempts === maxAttempts) {
			msgEl.textContent += " Login blocked.";
		}
	});
}

// --- Function to set up Rate Limiting demo ---
function setupRateLimitingDemo() {
	interactiveAreaDiv.innerHTML = `
		<div style="max-width:600px; margin-bottom:1rem;">
			<h4>What Is Rate Limiting?</h4>
			<p>Rate limiting restricts how many requests a client can make to an endpoint within a time window to prevent abuse and Denial‑of‑Service.</p>
			<pre style="background:#f4f4f4; padding:1rem; font-family: monospace;">
// Token Bucket Algorithm (pseudo‑code)
let tokens = capacity;
on each request:
  refill tokens up to capacity at rate per interval;
  if (tokens > 0) {
    tokens--;
    allow request;
  } else {
    reject request (429 Too Many Requests);
  }
			</pre>
		</div>
		<div style="display:flex; flex-direction:column; gap:0.5rem; max-width:400px;">
			<button id="rl-action" style="padding:0.5rem;">Send Request</button>
			<p>Requests sent: <span id="rl-count">0</span></p>
			<p id="rl-message" style="color:#f66;"></p>
		</div>
		<h4>Developer Guidelines</h4>
		<h5>Do:</h5>
		<ul>
			<li>Define consistent limits per user, IP, or API key.</li>
			<li>Use proven algorithms (token/leaky bucket) with sliding windows.</li>
			<li>Return clear headers (e.g., <code>Retry-After</code>) on limit errors.</li>
		</ul>
		<h5>Don't:</h5>
		<ul>
			<li>Implement naive counters without expiration—memory leaks risk.</li>
			<li>Fail silently—always communicate rate limit status to clients.</li>
			<li>Use the same limit for every endpoint; tailor limits to usage patterns.</li>
		</ul>
	`;
	let count = 0;
	const limit = 10;
	const windowMs = 60000; // 1 minute
	const countEl2 = document.getElementById("rl-count");
	const msgEl2 = document.getElementById("rl-message");
	const btn = document.getElementById("rl-action");
	btn.addEventListener("click", () => {
		if (count >= limit) {
			msgEl2.textContent = "Rate limit exceeded. Please wait.";
			return;
		}
		count++;
		countEl2.textContent = count;
		msgEl2.textContent = "Request successful!";
		setTimeout(() => {
			count = Math.max(0, count - 1);
			countEl2.textContent = count;
		}, windowMs);
	});
}

// --- Function to set up OAuth2 demo using Mermaid ---
function setupOauth2Demo() {
	interactiveAreaDiv.innerHTML = `
	<div style="max-width:800px; margin:0 auto; text-align:left;">
	  <h4>What is OAuth2?</h4>
	  <p>OAuth 2.0 is an authorization framework that enables applications to obtain limited access to user accounts on an HTTP service, delegate access without sharing credentials, and support Single Sign-On (SSO) or delegated API access.</p>

	  <h4>Step-by-Step Flow</h4>
	  <pre class="mermaid">
sequenceDiagram
    participant User
    participant Client
    participant AuthServer as Auth Server
    participant ResourceServer as Resource Server
    User->>Client: Request OAuth URL
    Client->>AuthServer: Redirect with client_id & state
    AuthServer-->>Client: Redirect back with authorization code
    Client->>AuthServer: Exchange code for access token
    Client->>ResourceServer: Access protected resource with token
     </pre>

	  <h4>When & Why to Use</h4>
	  <ul>
	    <li>Delegated access without exposing user credentials.</li>
	    <li>SSO with social or enterprise identity providers.</li>
	    <li>Secure API access for mobile and web clients.</li>
	  </ul>

	  <h4>Pros</h4>
	  <ul>
	    <li>Standardized flows support multiple clients and identity providers.</li>
	    <li>Granular scopes limit access to specific resources.</li>
	    <li>Works well in distributed microservice architectures.</li>
	  </ul>

	  <h4>Cons</h4>
	  <ul>
	    <li>Complexity of multiple flows (Authorization Code, Implicit, Client Credentials, etc.).</li>
	    <li>Requires careful handling of tokens and redirect URIs.</li>
	  </ul>

	  <h4>Developer Guidelines</h4>
	  <h5>Do:</h5>
	  <ul>
	    <li>Use the Authorization Code flow with PKCE for public clients.</li>
	    <li>Validate <code>state</code> and all token claims server-side.</li>
	    <li>Register and enforce exact redirect URIs to prevent open redirects.</li>
	  </ul>
	  <h5>Don't:</h5>
	  <ul>
	    <li>Embed client secrets in frontend code.</li>
	    <li>Use the Implicit flow for new applications (it's deprecated).</li>
	    <li>Skip HTTPS—always transmit tokens over secure channels.</li>
	  </ul>
	</div>
	`;
	mermaid.run();
}

// --- Function to set up Input Validation demo ---
function setupInputValidationDemo() {
	const emailInput = document.getElementById("email-input");
	const emailResult = document.getElementById("email-result");
	const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	const validateEmail = () => {
		if (emailRe.test(emailInput.value)) {
			emailResult.textContent = "✅ Valid email";
			emailResult.style.color = "green";
		} else {
			emailResult.textContent = "❌ Invalid email";
			emailResult.style.color = "red";
		}
	};
	emailInput.addEventListener("input", validateEmail);
	validateEmail();

	const numInput = document.getElementById("num-input");
	const numResult = document.getElementById("num-result");
	const validateNum = () => {
		const val = Number(numInput.value);
		if (val >= 1 && val <= 100) {
			numResult.textContent = "✅ Within range";
			numResult.style.color = "green";
		} else {
			numResult.textContent = "❌ Out of range";
			numResult.style.color = "red";
		}
	};
	numInput.addEventListener("input", validateNum);
	validateNum();
}

// --- Initialization ---
populateConceptList();
// Auto-select first concept on load
requestAnimationFrame(() => {
	const firstButton = conceptListUl.querySelector("button");
	if (firstButton) firstButton.click();
});

// --- Mobile menu toggle ---
document.getElementById("menu-toggle")?.addEventListener("click", () => {
	document.getElementById("app")?.classList.toggle("menu-open");
});

// Export for testing purposes
export { handleConceptClick, populateConceptList, securityConcepts };
