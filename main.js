import mermaid from "mermaid"; 

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
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4 class="text-lg font-semibold text-blue-800 dark:text-blue-300">Authentication (AuthN)</h4>
				<div class="space-y-3">
					<p class="text-sm">Authentication is the process of verifying a user's identity by checking credentials such as username and password. It ensures that the person or entity attempting to access a system is who they claim to be.</p>
					<p class="text-sm"><strong>Example:</strong> Logging in as <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">jane.doe@example.com</code> with your password confirms your identity to the system.</p>
					<p class="text-sm"><em>Limitation of AuthN only:</em> Any authenticated user—malicious or not—could attempt to access sensitive features simply by being logged in. For instance, a regular user might call admin APIs directly and gain unauthorized access if no additional checks exist.</p>
				</div>

				<h4 class="text-lg font-semibold text-blue-800 dark:text-blue-300">Authorization (AuthZ)</h4>
				<div class="space-y-3">
					<p class="text-sm">Authorization determines what actions or resources an authenticated user is allowed to access. It enforces policies and permissions to ensure users only perform actions they are entitled to.</p>
					<p class="text-sm"><strong>Example:</strong> A user with the role <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">guest</code> should not access <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">/admin/dashboard</code>, regardless of being authenticated.</p>
					<p class="text-sm"><em>Why AuthZ is crucial in large applications:</em> Big apps often have many roles, resources, and microservices. Proper authorization enforces least privilege, prevents privilege escalation across modules, and ensures each user can only access their permitted data and actions.</p>
				</div>
			</div>
		`,
	},
	{
		id: "jwt",
		title: "JWT (JSON Web Token)",
		description:
			"A compact, signed token used to transmit identity and claims securely.",
		interactiveHTML: `
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>Where JWTs Are Used</h4>
				<ul>
					<li>Authentication tokens in SPAs and mobile apps</li>
					<li>Authorization between microservices in distributed systems</li>
					<li>Secure information exchange (e.g., OAuth/OIDC flows)</li>
				</ul>
				<h4 class="mt-8">Why Use JWT</h4>
				<ul>
					<li>Compact and URL-safe</li>
					<li>Self-contained: carries its own claims (no server session state)</li>
					<li>Stateless: scales easily across multiple servers</li>
				</ul>
				<h4 class="mt-8">JWT Structure</h4>
				<pre><code class="block bg-gray-100 dark:bg-gray-700 p-2 rounded font-mono text-sm">header.payload.signature</code></pre>
				<ul>
					<li><strong>Header:</strong> Algorithm & token type (Base64Url JSON)</li>
					<li><strong>Payload:</strong> Claims like user ID, roles</li>
					<li><strong>Signature:</strong> Verifies integrity</li>
				</ul>
				<h4 class="mt-8">Pros</h4>
				<ul>
					<li>No need for server-side session store</li>
					<li>Easily scalable and CORS-friendly</li>
					<li>Supports rich, typed claims</li>
				</ul>
				<h4 class="mt-8">Cons</h4>
				<ul>
					<li>Difficult to revoke before expiry</li>
					<li>Larger token size than opaque tokens</li>
					<li>Risk if stolen: bearer tokens grant access</li>
					<li>May expose data if not encrypted</li>
				</ul>
				<h4 class="mt-8">Developer Guidelines</h4>
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
			</div>
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
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>Open Redirect Flow</h4>
				<pre class="mermaid bg-gray-100 dark:bg-gray-700 p-2 rounded">
flowchart LR
	A[User clicks link on trusted.com] --> B[trusted.com/redirect?url=target]
	B --> C[Server redirects to target URL]
	C --> D[User lands on the destination site]
				</pre>

				<h4 class="mt-8">Attack Scenario</h4>
				<p>An attacker sends: <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded text-sm break-all">https://trusted.com/redirect?url=https://malicious.com</code> via email or social media. The user sees the <em>trusted.com</em> domain and clicks, but ends up on <strong>malicious.com</strong>.</p>

				<h4 class="mt-8">Impact & Usage by Attackers</h4>
				<ul>
					<li>Phishing: display fake login pages under a trusted domain to harvest credentials.</li>
					<li>Malware distribution: host malicious downloads without raising suspicion.</li>
					<li>Filter bypass: trusted domains often bypass email and web filters.</li>
				</ul>
			</div>
		`,
	},
	{
		id: "session-hijacking",
		title: "Session Hijacking",
		description:
			"Stealing a user's session ID (often from a cookie) to impersonate them.",
		interactiveHTML: `
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>Session Hijacking Flow</h4>
				<pre class="mermaid bg-gray-100 dark:bg-gray-700 p-2 rounded">
flowchart LR
	A[User logs in] --> B[Server sets session cookie]
	B --> C[Attacker steals cookie via XSS/sniffing]
	C --> D[Attacker sends cookie with requests]
	D --> E[Server accepts and impersonates user]
				</pre>

				<h4 class="mt-8">Attack Methods</h4>
				<ul>
					<li>XSS: malicious script reads <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">document.cookie</code>.</li>
					<li>Network sniffing: HTTP traffic exposes cookies when not encrypted.</li>
					<li>Malware: system exploits extract session cookies.</li>
					<li>Predictable session IDs: brute-forcing weak identifiers.</li>
				</ul>

				<h4 class="mt-8">Developer Guidelines</h4>
				<h5>Do:</h5>
				<ul>
					<li>Use <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Secure</code>, <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">HttpOnly</code>, and <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">SameSite</code> flags on cookies.</li>
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
			</div>
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
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>Why Password Hashing is Needed</h4>
				<p>Storing passwords in plain text is extremely risky. If a database is breached, all user credentials would be immediately exposed, leading to widespread account compromises.</p>

				<h4 class="mt-8">What Password Hashing Prevents</h4>
				<p>Password hashing prevents attackers from reading passwords directly from a stolen database. Even if an attacker gains access to the hashed passwords, they cannot easily reverse the hash to get the original password, especially when strong, slow hashing algorithms and unique salts are used. This significantly limits the damage of a data breach.</p>

				<h4 class="mt-8">When to Hash Passwords</h4>
				<p>Passwords should be hashed as soon as they are received from the user, typically during account creation or password change operations. The hashed password, along with a unique salt, should be stored in the database instead of the plain-text password. When a user attempts to log in, the entered password should be hashed with the stored salt and compared to the stored hash.</p>

				<h4 class="mt-8">Best Practices</h4>
				<ul>
					<li>Use slow, adaptive algorithms (bcrypt, Argon2) with high work factors.</li>
					<li>Generate a unique salt for each password.</li>
					<li>Optionally add a server-side pepper stored outside the database.</li>
				</ul>

				<h4 class="mt-8">Developer Guidelines</h4>
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
			</div>
		`,
	},
	{
		id: "salting",
		title: "Salting",
		description:
			"Adds randomness to passwords before hashing to prevent rainbow table attacks.",
		interactiveHTML: `
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>What is Salting?</h4>
				<p>A salt is a unique, random value added to each password <em>before</em> hashing. It prevents attackers from using precomputed rainbow tables to crack multiple passwords at once.</p>

				<h4 class="mt-8">Why Salting Works</h4>
				<p>Even if two users have the same password (e.g., "password123"), their unique salts result in completely different stored hashes. This forces attackers to compute hashes individually for each user, making rainbow table attacks infeasible.</p>
				<p>Hash Storage: <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">hash(salt + password)</code> alongside the unique <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">salt</code>.</p>

				<h4 class="mt-8">Code Example (Reusing bcrypt logic)</h4>
				<pre><code class="language-javascript block bg-gray-100 dark:bg-gray-700 p-2 rounded font-mono text-sm overflow-x-auto">
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

				<h4 class="mt-8">Developer Guidelines</h4>
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
			</div>
		`,
	},
	{
		id: "tls",
		title: "TLS (Transport Layer Security)",
		description:
			"Encrypts traffic between client (browser) and server to prevent eavesdropping. (Successor to SSL)",
		interactiveHTML: `<div class="prose dark:prose-invert max-w-none space-y-6"><p>Provides:</p><ul><li><b>Encryption:</b> Prevents others from reading the data (padlock icon).</li><li><b>Authentication:</b> Verifies the server is who it claims to be (using certificates).</li><li><b>Integrity:</b> Ensures data hasn't been tampered with in transit.</li></ul><p>Uses a handshake process to establish a secure connection.</p></div>`,
	},
	{
		id: "hsts",
		title: "HSTS (HTTP Strict Transport Security)",
		description:
			"Forces browsers to only connect over HTTPS, even if the user types HTTP.",
		interactiveHTML: `
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>What is HSTS?</h4>
				<p>HTTP Strict Transport Security (HSTS) is a web security policy mechanism that helps to protect websites against man-in-the-middle attacks, particularly protocol downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol.</p>

				<h4 class="mt-8">How HSTS Works</h4>
				<p>When a browser connects to a website over HTTPS that has HSTS enabled, the server includes a <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Strict-Transport-Security</code> header in the response. This header tells the browser to automatically convert any future attempts to access the site using HTTP to HTTPS for a specified period (<code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">max-age</code>). This prevents attackers from tricking users into connecting over insecure HTTP, even if they explicitly type <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">http://</code>.</p>

				<pre><code class="language-http block bg-gray-100 dark:bg-gray-700 p-2 rounded font-mono text-sm overflow-x-auto">
Strict-Transport-Security: max-age=31536000; includeSubDomains
				</code></pre>

				<ul>
					<li><code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">max-age</code>: The time in seconds that the browser should remember the HSTS setting. A year is a common value (31536000 seconds).</li>
					<li><code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">includeSubDomains</code>: An optional directive that applies the HSTS policy to all subdomains of the site as well.</li>
				</ul>

				<h4 class="mt-8">Why HSTS is Important</h4>
				<p>HSTS is a crucial layer of defense against attacks that rely on downgrading a user's connection from secure HTTPS to insecure HTTP. Without HSTS, an attacker could intercept a user's initial HTTP request and redirect them to a malicious site or capture sensitive information transmitted over the insecure connection. HSTS ensures that once a browser has seen the header, it will only communicate with the site over HTTPS, even on subsequent visits or if the user tries to access the site via an HTTP link.</p>

				<h4 class="mt-8">Developer Guidelines</h4>
				<h5>Do:</h5>
				<ul>
					<li>Implement HSTS on all websites that handle sensitive information or require secure connections.</li>
					<li>Set a sufficiently long <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">max-age</code> to ensure users are protected for an extended period.</li>
					<li>Consider including the <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">includeSubDomains</code> directive if you want the policy to apply to your subdomains.</li>
					<li>Submit your domain to the HSTS preload list to hardcode the policy in browsers.</li>
				</ul>
				<h5>Don't:</h5>
				<ul>
					<li>Implement HSTS without ensuring your entire site and all subdomains are fully accessible over HTTPS first. Otherwise, you risk making your site inaccessible to users.</li>
					<li>Use a very short <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">max-age</code>, as this reduces the effectiveness of the policy.</li>
				</ul>
			</div>
		`,
	},
	{
		id: "security-headers",
		title: "Security Headers",
		description:
			"HTTP headers like Content-Security-Policy and X-Frame-Options protect web apps.",
		interactiveHTML: `
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>Common Security Headers</h4>
				<p>Security headers are HTTP response headers that instruct browsers to enforce security policies. Properly configured, they help protect against XSS, clickjacking, MIME sniffing, and other attacks.</p>
				<ul>
					<li><strong>Content-Security-Policy (CSP):</strong> Restricts resource loading (scripts, images, styles) to trusted sources. Prevents XSS.</li>
					<li><strong>X-Frame-Options:</strong> Controls whether the site can be embedded in frames/iframes. Protects against clickjacking (<code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">DENY</code> or <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">SAMEORIGIN</code>).</li>
					<li><strong>X-Content-Type-Options:</strong> Prevents MIME sniffing by enforcing declared <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Content-Type</code> (<code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">nosniff</code>).</li>
					<li><strong>Referrer-Policy:</strong> Limits the information sent in the Referer header. Enhances privacy.</li>
					<li><strong>Permissions-Policy:</strong> Specifies which browser features (camera, microphone, geolocation) are allowed.</li>
				</ul>

				<h4 class="mt-8">Why They Matter</h4>
				<ul>
					<li><strong>CSP:</strong> Blocks unauthorized scripts and mixed content.</li>
					<li><strong>Frame Options:</strong> Prevents clickjacking attacks that trick users into clicking hidden buttons.</li>
					<li><strong>MIME Sniffing:</strong> Forces browsers to honor declared content types.</li>
					<li><strong>Referrer-Policy:</strong> Protects user privacy by controlling what URL data is exposed.</li>
					<li><strong>Permissions-Policy:</strong> Reduces risk by limiting powerful APIs.</li>
				</ul>

				<h4 class="mt-8">Developer Guidelines</h4>
				<h5>Do:</h5>
				<ul>
					<li>Define a strict CSP tailored to your application content and domains.</li>
					<li>Set <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">X-Frame-Options</code> to <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">SAMEORIGIN</code> or <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">DENY</code>, as needed.</li>
					<li>Enable <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">X-Content-Type-Options: nosniff</code> to prevent MIME sniffing.</li>
					<li>Choose a privacy-friendly Referrer Policy, e.g., <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">strict-origin-when-cross-origin</code>.</li>
					<li>Lock down Permissions-Policy to only the features you use.</li>
				</ul>
				<h5>Don't:</h5>
				<ul>
					<li>Rely solely on CSP for XSS prevention—combine with proper input validation and output encoding.</li>
					<li>Use overly permissive wildcard directives like <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">*</code> in CSP without necessity.</li>
					<li>Forget to update headers when your application's resource requirements change.</li>
				</ul>
			</div>
		`,
	},
	{
		id: "cors",
		title: "CORS (Cross-Origin Resource Sharing)",
		description:
			"Controls which domains can access your APIs from the browser.",
		interactiveHTML: `
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>Why CORS Matters</h4>
				<p>The browser's <strong>Same-Origin Policy</strong> blocks cross-origin requests by default to protect users. CORS allows servers to specify when such requests are safe.</p>

				<h4 class="mt-8">CORS Request Flow</h4>
				<pre class="mermaid bg-gray-100 dark:bg-gray-700 p-2 rounded">
 sequenceDiagram
	 Browser->>Server: Preflight OPTIONS (Origin, Access-Control-Request-Method, Access-Control-Request-Headers)
	 Server-->>Browser: 200 OK (Access-Control-Allow-Origin, Access-Control-Allow-Methods, Access-Control-Allow-Headers, [Access-Control-Allow-Credentials])
	 Browser->>Server: Actual Request (e.g., POST /data with Origin)
	 Server-->>Browser: 200 OK (Access-Control-Allow-Origin, [Access-Control-Allow-Credentials])
			 </pre>

				<h4 class="mt-8">Required Headers</h4>
				<h5>Browser Sends:</h5>
				<ul>
					<li><code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Origin</code>: Requesting origin (mandatory on all cross-origin requests).</li>
					<li><code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Access-Control-Request-Method</code>: Method for actual request (in preflight).</li>
					<li><code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Access-Control-Request-Headers</code>: Custom headers (in preflight if any).</li>
				</ul>

				<h5 class="mt-6">Server Responds:</h5>
				<ul>
					<li><code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Access-Control-Allow-Origin</code>: Allowed origin(s) (<code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">*</code> if no credentials).</li>
					<li><code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Access-Control-Allow-Methods</code>: Permitted HTTP methods (in preflight).</li>
					<li><code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Access-Control-Allow-Headers</code>: Permitted custom headers (in preflight).</li>
					<li><code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">Access-Control-Allow-Credentials</code>: Whether to allow cookies/credentials (if needed).</li>
				</ul>

				<h4 class="mt-8">Developer Guidelines</h4>
				<h5>Do:</h5>
				<ul>
					<li>Use explicit origins instead of <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">*</code> when allowing credentials.</li>
					<li>Allow only the HTTP methods and headers your API requires.</li>
					<li>Properly handle OPTIONS preflight requests on the server.</li>
				</ul>
				<h5>Don't:</h5>
				<ul>
					<li>Combine <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">*</code> with credentials.</li>
					<li>Expose sensitive data via overly permissive CORS.</li>
					<li>Ignore browser CORS errors—they indicate misconfiguration.</li>
				</ul>
			</div>
		`,
	},
	{
		id: "input-validation",
		title: "Input Validation",
		description:
			"Ensures only valid data is accepted to prevent injection and logic errors.",
	},
	{
		id: "least-privilege",
		title: "Principle of Least Privilege",
		description:
			"Give users and systems the minimum access needed to function.",
		interactiveHTML: `
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>What Is Least Privilege?</h4>
				<p>The Principle of Least Privilege means giving users, systems, and processes only the permissions they absolutely need to perform their tasks—and no more.</p>

				<h4 class="mt-8">Examples</h4>
				<ul>
					<li><strong>Users:</strong> A regular user account shouldn't have admin rights. An editor should only manage content, not server settings.</li>
					<li><strong>Services:</strong> Run web servers under a dedicated low-privilege account, not <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">root</code>.</li>
					<li><strong>API Keys:</strong> Issue keys with access limited to specific endpoints or data scopes.</li>
					<li><strong>Containers & VMs:</strong> Limit container capabilities and use separate namespaces.</li>
				</ul>

				<h4 class="mt-8">Benefits</h4>
				<ul>
					<li>Minimizes attack surface—compromised accounts have limited power.</li>
					<li>Prevents lateral movement—limits what an attacker can access next.</li>
					<li>Improves auditability—easy to track and review permissions.</li>
					<li>Supports defense in depth—combined with other controls reduces risk.</li>
				</ul>

				<h4 class="mt-8">Developer Guidelines</h4>
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
			</div>
		`,
	},
	{
		id: "secrets-management",
		title: "Secrets Management",
		description:
			"Store and access API keys or credentials securely, not in code or env files.",
		interactiveHTML: `
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>Why Not Commit Secrets?</h4>
				<p>Studies show over <strong>50%</strong> of developers accidentally commit secrets to repositories, often via unignored <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">.env</code> files, risking data exposure.</p>

				<h4 class="mt-8">Common Mistake</h4>
				<pre><code class="bad block bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 p-2 rounded font-mono text-sm overflow-x-auto">
// Accidentally added to source control via .env
API_KEY=sk_live_veryRealSecretKey...
DB_PASSWORD=SuperSecret123
</code></pre>

				<h4 class="mt-8">Secure Options</h4>
				<ul>
					<li><strong>Environment Variables:</strong> Keep <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">.env</code> local and add it to <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">.gitignore</code>.</li>
					<li><strong>Encrypted Configs:</strong> Use encrypted files with strict file-system permissions.</li>
					<li><strong>Secrets Stores:</strong> Use HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager for centralized management, auditing, and rotation.</li>
				</ul>

				<h4 class="mt-8">Developer Guidelines</h4>
				<h5>Do:</h5>
				<ul>
					<li>Add <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">.env</code> to <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">.gitignore</code> and never commit it.</li>
					<li>Integrate secret scanners (e.g., git-secrets, TruffleHog) in pre-commit or CI.</li>
					<li>Rotate secrets immediately upon any exposure.</li>
					<li>Grant minimal permissions and rotate periodically.</li>
				</ul>
				<h5>Don't:</h5>
				<ul>
					<li>Hard-code credentials directly in code or client assets.</li>
					<li>Share <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">.env</code> via email, chat, or public channels.</li>
					<li>Assume files won't be committed without automated checks.</li>
				</ul>
			</div>
		`,
	},
	{
		id: "security-auditing",
		title: "Security Auditing",
		description:
			"Regular checks on code, infra, and dependencies to spot vulnerabilities.",
		interactiveHTML: `
			<div class="prose dark:prose-invert max-w-none space-y-6">
				<h4>What is Security Auditing?</h4>
				<p>Security auditing is the ongoing process of evaluating code, infrastructure, and dependencies to uncover vulnerabilities before attackers can exploit them.</p>

				<h4 class="mt-8">Key Practices</h4>
				<ul>
					<li><strong>Code Reviews:</strong> Peer reviews to catch logic flaws and insecure patterns early.</li>
					<li><strong>Static Analysis (SAST):</strong> Automated tools (e.g., SonarQube, ESLint security plugins) analyze source code for vulnerabilities.</li>
					<li><strong>Dynamic Analysis (DAST):</strong> Runtime scanners (e.g., OWASP ZAP, Burp Suite) test the live application for security gaps.</li>
					<li><strong>Dependency Scanning:</strong> Tools like npm audit, Snyk, or Dependabot to identify and update vulnerable libraries.</li>
					<li><strong>Penetration Testing:</strong> Manual or automated simulated attacks to verify defenses and find complex issues.</li>
					<li><strong>Infrastructure Scans:</strong> Assess server/container configurations and network settings (e.g., Nessus, OpenSCAP).</li>
				</ul>

				<h4 class="mt-8">Why Continuous Auditing?</h4>
				<p>Integrating security checks into your development lifecycle ensures vulnerabilities are caught early and reduces risk of production incidents.</p>

				<h4 class="mt-8">Developer Guidelines</h4>
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
			</div>
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
	conceptListUl.innerHTML = ""; // Clear existing list items if any
	for (const concept of securityConcepts) {
		const li = document.createElement("li");
		const button = document.createElement("button");
		button.textContent = concept.title;
		button.dataset.conceptId = concept.id; // Store id for lookup
		// Apply Tailwind classes for base styling and hover/focus states
		// Added cursor-pointer explicitly
		button.className = `
            w-full text-left px-3 py-2 rounded-md text-sm font-medium cursor-pointer
            text-gray-700 dark:text-gray-300 
            hover:bg-gray-100 dark:hover:bg-gray-700 
            hover:text-gray-900 dark:hover:text-white
            focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500
        `;
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
		// Use innerHTML for the description paragraph to potentially render basic formatting
		// Added prose class to the parent container now, so this specific one is less critical
		conceptDescriptionP.innerHTML = concept.description || "";
		interactiveAreaDiv.innerHTML =
			concept.interactiveHTML ||
			'<p class="italic text-gray-500 dark:text-gray-400">No interactive demo for this concept yet.</p>';

		// Update active button style using Tailwind classes
		const buttons = document.querySelectorAll("#concept-list button");
		// Base classes including cursor-pointer
		const baseClasses = `
            w-full text-left px-3 py-2 rounded-md text-sm font-medium cursor-pointer
            text-gray-700 dark:text-gray-300 
            hover:bg-gray-100 dark:hover:bg-gray-700 
            hover:text-gray-900 dark:hover:text-white
            focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500
        `;
		const activeClasses =
			"bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-200 font-semibold";

		for (const btn of buttons) {
			// Reset to base, then add active if it matches
			btn.className = baseClasses;
			if (btn.dataset.conceptId === conceptId) {
				// Remove hover classes when active, apply active classes
				btn.classList.remove(
					"hover:bg-gray-100",
					"dark:hover:bg-gray-700",
					"hover:text-gray-900",
					"dark:hover:text-white",
					"text-gray-700",
					"dark:text-gray-300",
				);
				btn.classList.add(...activeClasses.split(" ").filter(Boolean));
			}
		}

		// Close sidebar on mobile after selection
		const sidebar = document.getElementById("concept-list");
		const overlay = document.getElementById("menu-overlay");
		// Check if sidebar exists and is currently open (translate-x-0)
		if (sidebar?.classList.contains("translate-x-0")) {
			sidebar.classList.add("-translate-x-full");
			sidebar.classList.remove("translate-x-0");
			overlay?.classList.add("hidden");
		}

		// Existing demo setup calls...
		if (conceptId === "xss") setupXssDemo();
		if (conceptId === "csrf") setupCsrfDemo();
		if (conceptId === "sql-injection") setupSqlInjectionDemo();
		if (conceptId === "brute-force") setupBruteForceDemo();
		if (conceptId === "rate-limiting") setupRateLimitingDemo();
		if (conceptId === "oauth2") setupOauth2Demo();
		if (conceptId === "input-validation") setupInputValidationDemo();

		// Render Mermaid diagrams if present
		// Ensure Mermaid can find the diagrams after innerHTML is set
		requestAnimationFrame(() => {
			try {
				// Use optional chaining on the element first
				const mermaidElements =
					interactiveAreaDiv?.querySelectorAll("pre.mermaid");
				// Check length after confirming elements exist
				if (mermaidElements && mermaidElements.length > 0) {
					mermaid.run({ nodes: mermaidElements });
				}
			} catch (e) {
				console.error("Mermaid rendering failed:", e);
			}
		});
	}
}

// --- Function to set up interactive XSS demo ---
function setupXssDemo() {
	interactiveAreaDiv.innerHTML = `
		<div class="bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 p-6 border border-gray-300 dark:border-gray-600 rounded-lg shadow-md">
			<h3 class="text-xl font-bold mb-4 text-blue-700 dark:text-blue-400 border-b border-gray-200 dark:border-gray-700 pb-2">XSS Interactive Demo</h3>
			<p class="text-sm mb-6">Cross-Site Scripting (XSS) lets attackers inject scripts into webpages. Modify the default payload below or enter your own code, then click <strong>Render</strong> to compare unsafe execution vs sanitized output.</p>
			
			<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
				<div class="bg-gray-50 dark:bg-gray-750 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
					<h4 class="text-lg font-semibold mb-3 text-gray-800 dark:text-gray-200">How XSS Is Performed:</h4>
					<ul class="space-y-2 list-disc pl-5">
						<li>Injecting unsanitized user input into HTML content or attributes (e.g., via forms, URLs, comments)</li>
						<li>Inserting <code class="bg-gray-200 dark:bg-gray-600 px-1 rounded text-red-600 dark:text-red-400">&lt;script&gt;</code> tags, event handlers (<code class="bg-gray-200 dark:bg-gray-600 px-1 rounded">onerror</code>, <code class="bg-gray-200 dark:bg-gray-600 px-1 rounded">onclick</code>), or malformed attributes</li>
						<li>Exploiting vulnerabilities in input validation or missing output encoding</li>
					</ul>
				</div>
				
				<div class="bg-gray-50 dark:bg-gray-750 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
					<h4 class="text-lg font-semibold mb-3 text-gray-800 dark:text-gray-200">What Attackers Can Do:</h4>
					<ul class="space-y-2 list-disc pl-5">
						<li>Steal session cookies or authentication tokens (<code class="bg-gray-200 dark:bg-gray-600 px-1 rounded">document.cookie</code>)</li>
						<li>Hijack user sessions, deface pages, or modify content</li>
						<li>Redirect users, perform unauthorized actions, or launch phishing attacks</li>
						<li>Deliver malware or keyloggers directly in the browser</li>
					</ul>
				</div>
			</div>
			
			<div class="mb-6">
				<label for="xss-input" class="block mb-2 text-sm font-medium">Enter HTML or script:</label>
				<textarea id="xss-input" rows="3" class="w-full font-mono text-sm p-3 border border-gray-300 dark:border-gray-600 rounded-md bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-blue-500 focus:border-blue-500" placeholder="Enter HTML or script here"></textarea>
				<button id="xss-render" class="mt-3 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">Render</button>
			</div>
			
			<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
				<div>
					<h4 class="mb-3 font-semibold text-red-700 dark:text-red-400 flex items-center">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
							<path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
						</svg>
						Unsafe Render
					</h4>
					<div id="xss-unsafe" class="border-2 border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 p-4 rounded-md min-h-[100px] overflow-auto"></div>
				</div>
				<div>
					<h4 class="mb-3 font-semibold text-green-700 dark:text-green-400 flex items-center">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
							<path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
						</svg>
						Sanitized Render
					</h4>
					<div id="xss-safe" class="border-2 border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-900/20 p-4 rounded-md min-h-[100px] whitespace-pre-wrap font-mono text-sm overflow-auto"></div>
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
		<div class="bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 p-6 border border-gray-300 dark:border-gray-600 rounded-lg shadow-md">
			<h3 class="text-xl font-bold mb-4 text-blue-700 dark:text-blue-400 border-b border-gray-200 dark:border-gray-700 pb-2">CSRF Interactive Demo</h3>
			
			<div class="flex flex-col lg:flex-row gap-8 mb-6">
				<div class="flex-1 border border-gray-300 dark:border-gray-600 rounded-md p-5 bg-gray-50 dark:bg-gray-750 shadow flex flex-col">
					<div class="flex-grow">
						<h4 class="text-lg font-semibold mb-3 text-gray-800 dark:text-gray-200 flex items-center">
							<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
								<path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
							</svg>
							Legitimate Form (includes token)
						</h4>
						<p class="text-sm text-gray-600 dark:text-gray-400 mb-3">This form is on your bank's official site and includes a hidden CSRF token tied to your session. The server verifies this token on each request and will reject any request with an incorrect or missing token.</p>
						<p class="text-sm text-gray-600 dark:text-gray-400 mb-4">Form submits to: <code class="text-xs bg-gray-200 dark:bg-gray-700 px-1 rounded">https://bank.example.com/transfer</code> (same origin as your bank, so cookies are sent automatically)</p>
					</div>
					<form id="bank-form" action="https://bank.example.com/transfer" method="POST" class="space-y-4 mt-auto">
						<input type="hidden" id="csrf-hidden" value="abc123" />
						<div class="flex items-center mb-3">
							<label for="legit-to" class="w-24 text-sm font-medium">To Account:</label>
							<input id="legit-to" type="text" value="friendAcc" class="flex-1 p-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 focus:ring-blue-500 focus:border-blue-500"/>
						</div>
						<div class="flex items-center mb-3">
							<label for="legit-amt" class="w-24 text-sm font-medium">Amount:</label>
							<input id="legit-amt" type="number" value="100" class="flex-1 p-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 focus:ring-blue-500 focus:border-blue-500"/>
						</div>
						<div class="pl-24">
							<button type="button" id="legit-submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">Send</button>
						</div>
					</form>
				</div>
				<div class="flex-1 border-2 border-red-300 dark:border-red-600 rounded-md p-5 bg-red-50 dark:bg-red-900/20 shadow flex flex-col">
					<div class="flex-grow">
						<h4 class="text-lg font-semibold mb-3 text-red-700 dark:text-red-400 flex items-center">
							<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
								<path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
							</svg>
							Malicious Form (no token)
						</h4>
						<p class="text-sm text-red-700 dark:text-red-300 mb-3">On a phishing website controlled by an attacker, a form submits to your bank's transfer endpoint but omits the CSRF token. Because you are logged in, the browser automatically includes your bank's session cookies with this request, so without server-side token validation the attacker could transfer funds without your knowledge.</p>
						<p class="text-sm text-red-700 dark:text-red-300 mb-4">Although hosted on <code class="text-xs bg-red-200 dark:bg-red-800 px-1 rounded">https://evil-phish.com</code>, this form also submits to: <code class="text-xs bg-red-200 dark:bg-red-800 px-1 rounded">https://bank.example.com/transfer</code>, so the browser still sends your bank cookies.</p>
					</div>
					<form id="mal-form" action="https://bank.example.com/transfer" method="POST" class="space-y-4 mt-auto">
						<div class="flex items-center mb-3">
							<label for="mal-to" class="w-24 text-sm font-medium">To Account:</label>
							<input id="mal-to" type="text" value="attackerAcc" class="flex-1 p-2 border border-red-300 dark:border-red-600 rounded bg-white dark:bg-red-800/30 focus:ring-red-500 focus:border-red-500"/>
						</div>
						<div class="flex items-center mb-3">
							<label for="mal-amt" class="w-24 text-sm font-medium">Amount:</label>
							<input id="mal-amt" type="number" value="1000" class="flex-1 p-2 border border-red-300 dark:border-red-600 rounded bg-white dark:bg-red-800/30 focus:ring-red-500 focus:border-red-500"/>
						</div>
						<div class="pl-24">
							<button type="button" id="mal-submit" class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md text-sm font-medium focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors">Send</button>
						</div>
					</form>
				</div>
			</div>
			
			<div class="bg-gray-50 dark:bg-gray-750 p-5 rounded-lg border border-gray-200 dark:border-gray-700 mb-6">
				<h4 class="text-lg font-semibold mb-3 text-gray-800 dark:text-gray-200">Server Response:</h4>
				<pre id="csrf-server-log" class="bg-gray-100 dark:bg-gray-700 p-4 rounded-md min-h-[80px] text-sm font-mono whitespace-pre-wrap border border-gray-300 dark:border-gray-600"></pre>
			</div>
			
			<div class="bg-blue-50 dark:bg-blue-900/20 p-5 rounded-lg border border-blue-200 dark:border-blue-800 space-y-4">
				<h4 class="text-lg font-semibold text-blue-800 dark:text-blue-300">Why CSRF Token?</h4>
				<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
					<div>
						<p class="text-sm">Browsers automatically attach cookies (including session/authentication cookies) for a domain on any request, even if the request originates from another site. A CSRF token is a secret, user-specific value embedded in the legitimate site and checked server-side to ensure the request truly came from your application.</p>
					</div>
					<div>
						<p class="text-sm">As an additional mitigation, setting cookies with the <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">SameSite</code> attribute (e.g., <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">SameSite=Strict</code> or <code class="bg-gray-200 dark:bg-gray-700 px-1 rounded">SameSite=Lax</code>) can prevent them from being sent on cross-site requests.</p>
					</div>
				</div>
				
				<h4 class="text-lg font-semibold text-blue-800 dark:text-blue-300 mt-5">Best Practices:</h4>
				<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
					<ul class="space-y-2 list-disc pl-5 text-sm">
						<li>Generate a unique token per user session.</li>
						<li>Include the token in hidden form fields or custom headers.</li>
					</ul>
					<ul class="space-y-2 list-disc pl-5 text-sm">
						<li>Validate the token server-side on each request.</li>
						<li>Rotate tokens when users log out or periodically.</li>
					</ul>
				</div>
			</div>
		</div>
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
	interactiveAreaDiv.innerHTML = `
		<div class="bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 p-6 border border-gray-300 dark:border-gray-600 rounded-lg shadow-md">
			<h3 class="text-xl font-bold mb-4 text-blue-700 dark:text-blue-400 border-b border-gray-200 dark:border-gray-700 pb-2">SQL Injection Demo</h3>
			
			<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
				<div class="bg-gray-50 dark:bg-gray-750 p-5 rounded-lg border border-gray-200 dark:border-gray-700">
					<h4 class="text-lg font-semibold mb-3 text-gray-800 dark:text-gray-200">How SQL Injection Works:</h4>
					<ul class="space-y-2 list-disc pl-5 mb-4">
						<li>An attacker injects SQL syntax by including special characters like <code class="bg-gray-200 dark:bg-gray-600 px-1 rounded">'</code>.</li>
						<li>Using <code class="bg-gray-200 dark:bg-gray-600 px-1 rounded">--</code> comments out the rest of the WHERE clause (e.g., the password check).</li>
						<li>Example: <code class="block bg-gray-200 dark:bg-gray-600 p-2 rounded text-sm overflow-x-auto my-2">SELECT * FROM users WHERE username = 'admin' --' AND password = 'irrelevant';</code> becomes <code class="block bg-gray-200 dark:bg-gray-600 p-2 rounded text-sm overflow-x-auto my-2">SELECT * FROM users WHERE username = 'admin'</code></li>
						<li>This bypasses authentication and grants unauthorized access.</li>
					</ul>
					<p class="text-sm font-medium">The prefilled malicious payload demonstrates this bypass.</p>
				</div>
				
				<div class="bg-indigo-50 dark:bg-indigo-900/20 p-5 rounded-lg border border-indigo-200 dark:border-indigo-800">
					<div class="flex flex-col gap-4">
						<h4 class="text-lg font-semibold text-indigo-800 dark:text-indigo-300">Login Form</h4>
						<div class="space-y-4">
							<label class="block text-sm font-medium">Username: <input id="sql-user" type="text" value="admin' --" class="w-full p-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-blue-500 focus:border-blue-500"></label>
							<label class="block text-sm font-medium">Password: <input id="sql-pass" type="text" value="irrelevant" class="w-full p-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-blue-500 focus:border-blue-500"></label>
							<button id="sql-run" class="self-start px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-md text-sm font-medium focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors">Run Demo</button>
						</div>
					</div>
				</div>
			</div>
			
			<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
				<div>
					<h4 class="mb-3 font-semibold text-red-700 dark:text-red-400 flex items-center">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
							<path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
						</svg>
						Unsafe Query & Result
					</h4>
					<pre id="sql-unsafe" class="border-2 border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 p-4 rounded-md min-h-[120px] font-mono text-sm overflow-x-auto whitespace-pre-wrap"></pre>
				</div>
				<div>
					<h4 class="mb-3 font-semibold text-green-700 dark:text-green-400 flex items-center">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
							<path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
						</svg>
						Safe (Parameterized) Query & Result
					</h4>
					<pre id="sql-safe" class="border-2 border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-900/20 p-4 rounded-md min-h-[120px] font-mono text-sm overflow-x-auto whitespace-pre-wrap"></pre>
				</div>
			</div>
			
			<div class="bg-blue-50 dark:bg-blue-900/20 p-5 rounded-lg border border-blue-200 dark:border-blue-800">
				<h4 class="text-lg font-semibold text-blue-800 dark:text-blue-300 mb-4">Developer Guidelines</h4>
				<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
					<div>
						<h5 class="font-semibold mb-2 text-blue-700 dark:text-blue-400">Do:</h5>
						<ul class="space-y-2 list-disc pl-5 text-sm">
							<li>Use parameterized queries or prepared statements.</li>
							<li>Validate and sanitize all user inputs.</li>
							<li>Use ORM frameworks that handle escaping automatically.</li>
						</ul>
					</div>
					<div>
						<h5 class="font-semibold mb-2 text-blue-700 dark:text-blue-400">Don't:</h5>
						<ul class="space-y-2 list-disc pl-5 text-sm">
							<li>Concatenate user input directly into SQL queries.</li>
							<li>Rely solely on client-side validation.</li>
							<li>Trust any user-supplied data without server-side verification.</li>
						</ul>
					</div>
				</div>
			</div>
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
		<div class="max-width-xl mb-4 prose prose-sm dark:prose-invert space-y-3">
			<h4>What Is a Brute Force Attack?</h4>
			<p>A brute force attack systematically tries all possible passwords or tokens until the correct one is found, risking unauthorized access and lockouts.</p>
			<p><strong>Impact:</strong> Account compromise, resource exhaustion, data breaches.</p>
		</div>
		<div class="flex flex-col gap-2 max-width-xs">
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
		<div class="max-width-xl mb-4 prose prose-sm dark:prose-invert space-y-3">
			<h4>What Is Rate Limiting?</h4>
			<p>Rate limiting restricts how many requests a client can make to an endpoint within a time window to prevent abuse and Denial‑of‑Service.</p>
			<pre class="bg-gray-100 dark:bg-gray-700 p-3 rounded font-mono text-xs overflow-x-auto">
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
		<div class="flex flex-col gap-2 max-width-xs">
			<button id="rl-action" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">Send Request</button>
			<p class="text-sm mt-1">Requests sent in last 10s: <span id="rl-count">0</span> / 5</p>
			<p id="rl-message" class="text-sm min-h-[1.25em] font-medium"></p>
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
	let requestTimestamps = [];
	const limit = 5;
	const windowMs = 10000; // 10 seconds
	const countEl = document.getElementById("rl-count");
	const msgEl = document.getElementById("rl-message");
	const btn = document.getElementById("rl-action");

	function updateCount() {
		const now = Date.now();
		// Filter out timestamps older than the window
		requestTimestamps = requestTimestamps.filter((ts) => now - ts < windowMs);
		countEl.textContent = requestTimestamps.length;
	}

	// Update count periodically to show requests expiring from the window
	const intervalId = setInterval(updateCount, 1000);

	// Clear interval when the concept changes
	const currentConceptObserver = new MutationObserver(() => {
		if (!document.contains(interactiveAreaDiv)) {
			clearInterval(intervalId);
			currentConceptObserver.disconnect();
		} else if (currentConceptId !== "rate-limiting") {
			clearInterval(intervalId);
			currentConceptObserver.disconnect();
		}
	});
	currentConceptObserver.observe(document.body, {
		childList: true,
		subtree: true,
	});

	btn.addEventListener("click", () => {
		updateCount(); // Ensure count is up-to-date before checking limit

		if (requestTimestamps.length >= limit) {
			msgEl.classList.remove("text-green-600", "dark:text-green-400");
			msgEl.classList.add("text-red-600", "dark:text-red-400");
			msgEl.textContent = "Rate limit exceeded. Please wait.";
			return;
		}

		requestTimestamps.push(Date.now());
		countEl.textContent = requestTimestamps.length;
		msgEl.classList.remove("text-red-600", "dark:text-red-400");
		msgEl.classList.add("text-green-600", "dark:text-green-400");
		msgEl.textContent = "Request successful!";
	});
}

// --- Function to set up OAuth2 demo using Mermaid ---
function setupOauth2Demo() {
	interactiveAreaDiv.innerHTML = `
	<div class="max-width-3xl mx-auto text-left prose dark:prose-invert space-y-6">
	  <h4>What is OAuth2?</h4>
	  <p>OAuth 2.0 is an authorization framework that enables applications to obtain limited access to user accounts on an HTTP service, delegate access without sharing credentials, and support Single Sign-On (SSO) or delegated API access.</p>

	  <h4 class="mt-8">Step-by-Step Flow (Authorization Code)</h4>
	  <pre class="mermaid">
sequenceDiagram
    participant User
    participant Client
    participant AuthServer as Auth Server
    participant ResourceServer as Resource Server
    User->>Client: Initiates login/action
    Client->>AuthServer: Redirect user to Auth Server (with client_id, scope, state, redirect_uri)
    Note over User, AuthServer: User authenticates & grants consent
    AuthServer-->>Client: Redirect back to client app (with authorization code & state)
    Client->>AuthServer: Exchanges authorization code (with client_id, client_secret, code, redirect_uri) for tokens
    AuthServer-->>Client: Returns Access Token (& Refresh Token)
    Client->>ResourceServer: Makes API request (Authorization: Bearer [Access Token])
     </pre>

	  <h4 class="mt-8">When & Why to Use</h4>
	  <ul>
	    <li>Delegated access without exposing user credentials.</li>
	    <li>SSO with social or enterprise identity providers.</li>
	    <li>Secure API access for mobile and web clients.</li>
	  </ul>

	  <h4 class="mt-8">Pros</h4>
	  <ul>
	    <li>Standardized flows support multiple clients and identity providers.</li>
	    <li>Granular scopes limit access to specific resources.</li>
	    <li>Works well in distributed microservice architectures.</li>
	  </ul>

	  <h4 class="mt-8">Cons</h4>
	  <ul>
	    <li>Complexity of multiple flows (Authorization Code, Implicit, Client Credentials, etc.).</li>
	    <li>Requires careful handling of tokens and redirect URIs.</li>
	  </ul>

	  <h4 class="mt-8">Developer Guidelines</h4>
	  <h5>Do:</h5>
	  <ul>
	    <li>Use the Authorization Code flow with PKCE for public clients.</li>
	    <li>Validate <code>state</code> parameter to prevent CSRF.</li>
	    <li>Validate all token claims (issuer, audience, expiry) server-side.</li>
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
	// Ensure the HTML is injected before trying to get elements
	interactiveAreaDiv.innerHTML = `
		<h4 class="text-lg font-semibold mb-3">Input Validation Demo</h4>
		<div class="flex flex-wrap gap-8 mb-4">
			<div>
				<label for="email-input" class="block text-sm font-medium mb-1">Email Format</label>
				<input id="email-input" placeholder="user@example.com" value="<script>alert('XSS')</script>@example.com" class="p-2 border border-gray-300 dark:border-gray-600 rounded w-60 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-blue-500 focus:border-blue-500" />
				<p id="email-result" class="text-sm mt-1 min-h-[1.25em] font-medium"></p>
			</div>
			<div>
				<label for="num-input" class="block text-sm font-medium mb-1">Number Range (1–100)</label>
				<input id="num-input" type="number" placeholder="Enter number" value="150" class="p-2 border border-gray-300 dark:border-gray-600 rounded w-32 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-blue-500 focus:border-blue-500" />
				<p id="num-result" class="text-sm mt-1 min-h-[1.25em] font-medium"></p>
			</div>
		</div>
		<div class="prose dark:prose-invert max-w-none mt-4 space-y-3">
			<h4>Why It Matters</h4>
			<p>Broken or malicious inputs can lead to XSS, logic errors, or security vulnerabilities if not properly validated or sanitized on the server-side. Client-side validation improves UX but is not a security measure.</p>
		</div>
	`;

	const emailInput = document.getElementById("email-input");
	const emailResult = document.getElementById("email-result");
	const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Basic regex, real validation is more complex

	const validateEmail = () => {
		if (!emailInput || !emailResult) return; // Elements might not be ready immediately
		if (emailRe.test(emailInput.value)) {
			emailResult.textContent = "✅ Valid format (client-side)";
			emailResult.classList.remove("text-red-600", "dark:text-red-400");
			emailResult.classList.add("text-green-600", "dark:text-green-400");
		} else {
			emailResult.textContent = "❌ Invalid format (client-side)";
			emailResult.classList.remove("text-green-600", "dark:text-green-400");
			emailResult.classList.add("text-red-600", "dark:text-red-400");
		}
	};

	const numInput = document.getElementById("num-input");
	const numResult = document.getElementById("num-result");

	const validateNum = () => {
		if (!numInput || !numResult) return; // Elements might not be ready immediately
		const val = Number(numInput.value);
		if (numInput.value !== "" && val >= 1 && val <= 100) {
			numResult.textContent = "✅ Within range (client-side)";
			numResult.classList.remove("text-red-600", "dark:text-red-400");
			numResult.classList.add("text-green-600", "dark:text-green-400");
		} else {
			numResult.textContent = "❌ Out of range (client-side)";
			numResult.classList.remove("text-green-600", "dark:text-green-400");
			numResult.classList.add("text-red-600", "dark:text-red-400");
		}
	};

	// Add listeners only if elements exist
	if (emailInput) {
		emailInput.addEventListener("input", validateEmail);
		validateEmail(); // Initial validation
	}
	if (numInput) {
		numInput.addEventListener("input", validateNum);
		validateNum(); // Initial validation
	}
}

// --- Initialization ---
populateConceptList();
// Auto-select first concept on load
requestAnimationFrame(() => {
	const firstButton = conceptListUl.querySelector("button");
	if (firstButton) firstButton.click();
});

// --- Mobile menu toggle --- (Replace existing toggle logic)
document.getElementById("menu-toggle")?.addEventListener("click", () => {
	const sidebar = document.getElementById("concept-list");
	const overlay = document.getElementById("menu-overlay");

	if (sidebar && overlay) {
		const isOpen = sidebar.classList.contains("translate-x-0");
		if (isOpen) {
			// Close menu
			sidebar.classList.remove("translate-x-0");
			sidebar.classList.add("-translate-x-full");
			overlay.classList.add("hidden");
		} else {
			// Open menu
			sidebar.classList.remove("hidden"); // Ensure it's not display:none
			sidebar.classList.remove("-translate-x-full");
			sidebar.classList.add("translate-x-0");
			overlay.classList.remove("hidden");
		}
	}
});

// Add listener to overlay to close menu when clicked
document.getElementById("menu-overlay")?.addEventListener("click", () => {
	const sidebar = document.getElementById("concept-list");
	const overlay = document.getElementById("menu-overlay");
	if (sidebar && overlay) {
		// Check elements exist
		sidebar.classList.remove("translate-x-0");
		sidebar.classList.add("-translate-x-full");
		overlay.classList.add("hidden");
	}
});

// Export for testing purposes
export { handleConceptClick, populateConceptList, securityConcepts };
