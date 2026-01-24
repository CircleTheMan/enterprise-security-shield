<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Notifications;

/**
 * Email Notifier.
 *
 * Sends notifications via email using PHP's mail() or SMTP.
 *
 * USAGE:
 * ```php
 * // Using PHP mail()
 * $email = new EmailNotifier(['security@example.com'], 'alerts@example.com');
 *
 * // Using SMTP
 * $email = EmailNotifier::smtp(
 *     ['security@example.com'],
 *     'alerts@example.com',
 *     'smtp.example.com',
 *     587,
 *     'user@example.com',
 *     'password'
 * );
 *
 * $email->alert('🚨 Security Alert', 'IP banned: 1.2.3.4', [
 *     'reason' => 'Honeypot access',
 * ]);
 * ```
 */
class EmailNotifier implements NotifierInterface
{
    /** @var array<string> */
    private array $recipients;

    private string $fromAddress;

    private string $fromName;

    private ?string $smtpHost;

    private ?int $smtpPort;

    private ?string $smtpUser;

    private ?string $smtpPassword;

    private string $smtpEncryption;

    /**
     * @param array<string> $recipients Email recipients
     * @param string $fromAddress From email address
     * @param string $fromName From name
     */
    public function __construct(
        array $recipients,
        string $fromAddress,
        string $fromName = 'Security Shield',
    ) {
        $this->recipients = $recipients;
        $this->fromAddress = $fromAddress;
        $this->fromName = $fromName;
        $this->smtpHost = null;
        $this->smtpPort = null;
        $this->smtpUser = null;
        $this->smtpPassword = null;
        $this->smtpEncryption = 'tls';
    }

    /**
     * Create with SMTP configuration.
     *
     * @param array<string> $recipients Email recipients
     * @param string $fromAddress From email address
     * @param string $smtpHost SMTP host
     * @param int $smtpPort SMTP port
     * @param string $smtpUser SMTP username
     * @param string $smtpPassword SMTP password
     * @param string $encryption Encryption (tls, ssl, none)
     * @param string $fromName From name
     *
     * @return self
     */
    public static function smtp(
        array $recipients,
        string $fromAddress,
        string $smtpHost,
        int $smtpPort,
        string $smtpUser,
        string $smtpPassword,
        string $encryption = 'tls',
        string $fromName = 'Security Shield',
    ): self {
        $notifier = new self($recipients, $fromAddress, $fromName);
        $notifier->smtpHost = $smtpHost;
        $notifier->smtpPort = $smtpPort;
        $notifier->smtpUser = $smtpUser;
        $notifier->smtpPassword = $smtpPassword;
        $notifier->smtpEncryption = $encryption;

        return $notifier;
    }

    public function getName(): string
    {
        return 'email';
    }

    public function isConfigured(): bool
    {
        return !empty($this->recipients) && !empty($this->fromAddress);
    }

    public function send(string $message, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $subject = '[Security Shield] Notification';
        $body = $this->buildPlainBody($message, $context);

        return $this->sendEmail($subject, $body);
    }

    public function alert(string $title, string $message, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $subject = "[Security Shield] {$title}";
        $htmlBody = $this->buildHtmlBody($title, $message, $context);
        $plainBody = $this->buildPlainBody("{$title}\n\n{$message}", $context);

        return $this->sendEmail($subject, $htmlBody, $plainBody);
    }

    /**
     * Build plain text body.
     *
     * @param string $message
     * @param array<string, mixed> $context
     *
     * @return string
     */
    private function buildPlainBody(string $message, array $context): string
    {
        $body = $message . "\n\n";

        if (!empty($context)) {
            $body .= "Details:\n";
            $body .= str_repeat('-', 40) . "\n";

            foreach ($context as $key => $value) {
                $formattedKey = ucfirst(str_replace('_', ' ', $key));
                $formattedValue = is_array($value) ? json_encode($value) : (string) $value;
                $body .= "{$formattedKey}: {$formattedValue}\n";
            }
        }

        $body .= "\n" . str_repeat('-', 40) . "\n";
        $body .= 'Sent at: ' . date('Y-m-d H:i:s T') . "\n";
        $body .= "From: Security Shield\n";

        return $body;
    }

    /**
     * Build HTML body.
     *
     * @param string $title
     * @param string $message
     * @param array<string, mixed> $context
     *
     * @return string
     */
    private function buildHtmlBody(string $title, string $message, array $context): string
    {
        $contextHtml = '';

        if (!empty($context)) {
            $contextHtml = '<table style="width:100%;border-collapse:collapse;margin-top:20px;">';

            foreach ($context as $key => $value) {
                $formattedKey = htmlspecialchars(ucfirst(str_replace('_', ' ', $key)));
                $jsonEncoded = json_encode($value, JSON_PRETTY_PRINT);
                $formattedValue = is_array($value)
                    ? '<pre style="margin:0;background:#f5f5f5;padding:5px;">' . htmlspecialchars($jsonEncoded !== false ? $jsonEncoded : '{}') . '</pre>'
                    : htmlspecialchars((string) $value);

                $contextHtml .= <<<HTML
                    <tr>
                        <td style="padding:8px;border:1px solid #ddd;font-weight:bold;width:30%;">{$formattedKey}</td>
                        <td style="padding:8px;border:1px solid #ddd;">{$formattedValue}</td>
                    </tr>
                    HTML;
            }

            $contextHtml .= '</table>';
        }

        $titleHtml = htmlspecialchars($title);
        $messageHtml = nl2br(htmlspecialchars($message));
        $timestamp = date('Y-m-d H:i:s T');

        return <<<HTML
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>{$titleHtml}</title>
            </head>
            <body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <div style="background:#e74c3c;color:white;padding:15px;border-radius:5px 5px 0 0;">
                    <h1 style="margin:0;font-size:18px;">🛡️ {$titleHtml}</h1>
                </div>
                <div style="border:1px solid #ddd;border-top:none;padding:20px;border-radius:0 0 5px 5px;">
                    <p style="margin-top:0;">{$messageHtml}</p>
                    {$contextHtml}
                    <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
                    <p style="color:#888;font-size:12px;margin-bottom:0;">
                        Sent at: {$timestamp}<br>
                        From: Security Shield
                    </p>
                </div>
            </body>
            </html>
            HTML;
    }

    /**
     * Send email.
     *
     * @param string $subject Email subject
     * @param string $htmlBody HTML body
     * @param string|null $plainBody Plain text body (optional)
     *
     * @return bool
     */
    private function sendEmail(string $subject, string $htmlBody, ?string $plainBody = null): bool
    {
        if ($this->smtpHost !== null) {
            return $this->sendSmtp($subject, $htmlBody, $plainBody);
        }

        return $this->sendMail($subject, $htmlBody, $plainBody);
    }

    /**
     * Send using PHP mail().
     *
     * @param string $subject
     * @param string $htmlBody
     * @param string|null $plainBody
     *
     * @return bool
     */
    private function sendMail(string $subject, string $htmlBody, ?string $plainBody): bool
    {
        $to = implode(', ', $this->recipients);
        $boundary = md5(uniqid((string) time()));

        $headers = [
            "From: {$this->fromName} <{$this->fromAddress}>",
            "Reply-To: {$this->fromAddress}",
            'MIME-Version: 1.0',
            "Content-Type: multipart/alternative; boundary=\"{$boundary}\"",
        ];

        $body = "--{$boundary}\r\n";
        $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
        $body .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
        $body .= $plainBody ?? strip_tags($htmlBody);
        $body .= "\r\n\r\n--{$boundary}\r\n";
        $body .= "Content-Type: text/html; charset=UTF-8\r\n";
        $body .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
        $body .= $htmlBody;
        $body .= "\r\n\r\n--{$boundary}--";

        return @mail($to, $subject, $body, implode("\r\n", $headers));
    }

    /**
     * Send using SMTP socket.
     *
     * @param string $subject
     * @param string $htmlBody
     * @param string|null $plainBody
     *
     * @return bool
     */
    private function sendSmtp(string $subject, string $htmlBody, ?string $plainBody): bool
    {
        $socket = null;

        try {
            $host = $this->smtpHost;
            $port = $this->smtpPort ?? 587;

            if ($host === null) {
                error_log('EmailNotifier: SMTP host not configured');

                return false;
            }

            // Validate encryption setting
            if (!in_array($this->smtpEncryption, ['tls', 'ssl', 'none', null], true)) {
                error_log("EmailNotifier: Invalid SMTP encryption: {$this->smtpEncryption}");

                return false;
            }

            if ($this->smtpEncryption === 'ssl') {
                $host = 'ssl://' . $host;
            }

            // Connect with timeout
            $socket = @fsockopen($host, $port, $errno, $errstr, 10);

            if (!$socket) {
                error_log("EmailNotifier: Connection failed to {$host}:{$port} - {$errstr} ({$errno})");

                return false;
            }

            // Set stream timeout for all read operations
            stream_set_timeout($socket, 30);

            $this->smtpRead($socket);

            // EHLO
            $this->smtpCommand($socket, 'EHLO ' . gethostname());

            // STARTTLS for TLS
            if ($this->smtpEncryption === 'tls') {
                $this->smtpCommand($socket, 'STARTTLS');

                // Enable crypto with timeout protection
                $cryptoResult = @stream_socket_enable_crypto(
                    $socket,
                    true,
                    STREAM_CRYPTO_METHOD_TLS_CLIENT,
                );

                if ($cryptoResult !== true) {
                    error_log('EmailNotifier: TLS handshake failed');

                    return false;
                }

                $this->smtpCommand($socket, 'EHLO ' . gethostname());
            }

            // AUTH LOGIN
            if ($this->smtpUser !== null && $this->smtpPassword !== null) {
                $this->smtpCommand($socket, 'AUTH LOGIN');
                $this->smtpCommand($socket, base64_encode($this->smtpUser));
                $this->smtpCommand($socket, base64_encode($this->smtpPassword));
            }

            // MAIL FROM
            $this->smtpCommand($socket, "MAIL FROM:<{$this->fromAddress}>");

            // RCPT TO
            foreach ($this->recipients as $recipient) {
                $this->smtpCommand($socket, "RCPT TO:<{$recipient}>");
            }

            // DATA
            $this->smtpCommand($socket, 'DATA');

            // Build message
            $boundary = md5(uniqid((string) time()));
            $message = "From: {$this->fromName} <{$this->fromAddress}>\r\n";
            $message .= 'To: ' . implode(', ', $this->recipients) . "\r\n";
            $message .= "Subject: {$subject}\r\n";
            $message .= "MIME-Version: 1.0\r\n";
            $message .= "Content-Type: multipart/alternative; boundary=\"{$boundary}\"\r\n\r\n";
            $message .= "--{$boundary}\r\n";
            $message .= "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
            $message .= $plainBody ?? strip_tags($htmlBody);
            $message .= "\r\n\r\n--{$boundary}\r\n";
            $message .= "Content-Type: text/html; charset=UTF-8\r\n\r\n";
            $message .= $htmlBody;
            $message .= "\r\n\r\n--{$boundary}--\r\n";
            $message .= '.';

            $this->smtpCommand($socket, $message);

            // QUIT
            $this->smtpCommand($socket, 'QUIT');

            return true;

        } catch (\Throwable $e) {
            error_log('EmailNotifier: SMTP error - ' . $e->getMessage());

            return false;
        } finally {
            // Always close socket to prevent resource leak
            if ($socket !== null && is_resource($socket)) {
                @fclose($socket);
            }
        }
    }

    /**
     * Send SMTP command.
     *
     * @param resource $socket
     * @param string $command
     *
     * @return string
     */
    private function smtpCommand($socket, string $command): string
    {
        fwrite($socket, $command . "\r\n");

        return $this->smtpRead($socket);
    }

    /**
     * Read SMTP response.
     *
     * @param resource $socket
     *
     * @return string
     */
    private function smtpRead($socket): string
    {
        $response = '';
        $maxIterations = 100; // Prevent infinite loop
        $iterations = 0;

        while ($iterations < $maxIterations) {
            $line = fgets($socket, 512);

            // Check for timeout or error
            if ($line === false) {
                $meta = stream_get_meta_data($socket);
                if ($meta['timed_out']) {
                    error_log('EmailNotifier: SMTP read timeout');
                }
                break;
            }

            $response .= $line;

            // SMTP multi-line response ends when 4th char is space
            if (strlen($line) >= 4 && $line[3] === ' ') {
                break;
            }

            $iterations++;
        }

        return $response;
    }
}
