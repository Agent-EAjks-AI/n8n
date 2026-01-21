/**
 * Webhook utilities for sending evaluation results.
 */

import dns from 'node:dns/promises';

import type { RunSummary } from '../harness/harness-types';
import type { EvalLogger } from '../harness/logger';

/**
 * Mask a webhook URL for safe logging (hide potential tokens in path/query).
 */
function maskWebhookUrl(webhookUrl: string): string {
	const url = new URL(webhookUrl);
	return `${url.protocol}//${url.hostname}${url.port ? `:${url.port}` : ''}/***`;
}

/**
 * Webhook payload sent after evaluation completes.
 */
export interface WebhookPayload {
	experimentName: string;
	dataset: string;
	suite: string;
	summary: {
		totalExamples: number;
		passed: number;
		failed: number;
		errors: number;
		averageScore: number;
	};
	evaluatorAverages?: Record<string, number>;
	totalDurationMs: number;
	metadata: Record<string, unknown>;
}

/**
 * Check if an IP address is private/internal.
 */
function isPrivateIp(ip: string): boolean {
	// IPv4 private ranges
	const ipv4PrivatePatterns = [
		/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, // 127.0.0.0/8 (loopback)
		/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, // 10.0.0.0/8
		/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/, // 172.16.0.0/12
		/^192\.168\.\d{1,3}\.\d{1,3}$/, // 192.168.0.0/16
		/^169\.254\.\d{1,3}\.\d{1,3}$/, // 169.254.0.0/16 (link-local)
		/^0\.0\.0\.0$/, // 0.0.0.0
	];

	for (const pattern of ipv4PrivatePatterns) {
		if (pattern.test(ip)) {
			return true;
		}
	}

	// IPv6 private ranges
	const ipLower = ip.toLowerCase();
	if (
		ipLower === '::1' || // loopback
		ipLower.startsWith('fe80:') || // link-local
		ipLower.startsWith('fc') || // unique local (fc00::/7)
		ipLower.startsWith('fd') // unique local (fc00::/7)
	) {
		return true;
	}

	return false;
}

/**
 * Validate webhook URL for security (hostname-based checks only).
 * - Must be HTTPS
 * - Must not target localhost or private/internal IP addresses (SSRF prevention)
 *
 * Note: This performs synchronous hostname string validation.
 * For full SSRF protection, use validateWebhookUrlWithDns() which also resolves DNS.
 */
export function validateWebhookUrl(webhookUrl: string): void {
	const url = new URL(webhookUrl);

	// Enforce HTTPS
	if (url.protocol !== 'https:') {
		throw new Error(`Webhook URL must use HTTPS. Got: ${url.protocol}`);
	}

	const hostname = url.hostname.toLowerCase();

	// Block localhost (including IPv6 with brackets as URL.hostname returns)
	if (
		hostname === 'localhost' ||
		hostname === '127.0.0.1' ||
		hostname === '::1' ||
		hostname === '[::1]'
	) {
		throw new Error('Webhook URL cannot target localhost');
	}

	// Block private/internal IP ranges (SSRF prevention)
	if (isPrivateIp(hostname)) {
		throw new Error('Webhook URL cannot target private/internal IP addresses');
	}

	// Block common internal hostnames
	const blockedHostnames = ['internal', 'intranet', 'corp', 'private', 'local'];
	for (const blocked of blockedHostnames) {
		if (hostname === blocked || hostname.endsWith(`.${blocked}`)) {
			throw new Error(`Webhook URL cannot target internal hostname: ${hostname}`);
		}
	}
}

/**
 * Validate webhook URL with DNS resolution for comprehensive SSRF protection.
 * Resolves the hostname and validates that resolved IPs are not private/internal.
 */
export async function validateWebhookUrlWithDns(webhookUrl: string): Promise<void> {
	// First, run basic hostname validation
	validateWebhookUrl(webhookUrl);

	const url = new URL(webhookUrl);
	const hostname = url.hostname.toLowerCase();

	// Skip DNS resolution if hostname is already an IP address
	if (isPrivateIp(hostname)) {
		throw new Error('Webhook URL cannot target private/internal IP addresses');
	}

	// Resolve DNS and check all resolved IPs
	try {
		const addresses = await dns.resolve(hostname);
		for (const ip of addresses) {
			if (isPrivateIp(ip)) {
				throw new Error(
					'Webhook URL hostname resolves to a private/internal IP address',
				);
			}
		}

		// Also check IPv6 addresses if available
		try {
			const ipv6Addresses = await dns.resolve6(hostname);
			for (const ip of ipv6Addresses) {
				if (isPrivateIp(ip)) {
					throw new Error(
						'Webhook URL hostname resolves to a private/internal IP address',
					);
				}
			}
		} catch {
			// IPv6 resolution may fail if no AAAA records exist, which is fine
		}
	} catch (error) {
		// If DNS resolution fails, re-throw if it's our validation error
		if (error instanceof Error && error.message.includes('private/internal')) {
			throw error;
		}
		// For other DNS errors (ENOTFOUND, etc.), let the fetch fail naturally
	}
}

/**
 * Send evaluation results to a webhook URL.
 */
export async function sendWebhookNotification(params: {
	webhookUrl: string;
	summary: RunSummary;
	experimentName: string;
	dataset: string;
	suite: string;
	metadata: Record<string, unknown>;
	logger: EvalLogger;
}): Promise<void> {
	const { webhookUrl, summary, experimentName, dataset, suite, metadata, logger } = params;

	// Validate webhook URL for security (includes DNS resolution check)
	await validateWebhookUrlWithDns(webhookUrl);

	const payload: WebhookPayload = {
		experimentName,
		dataset,
		suite,
		summary: {
			totalExamples: summary.totalExamples,
			passed: summary.passed,
			failed: summary.failed,
			errors: summary.errors,
			averageScore: summary.averageScore,
		},
		evaluatorAverages: summary.evaluatorAverages,
		totalDurationMs: summary.totalDurationMs,
		metadata,
	};

	// Log masked URL to avoid exposing potential tokens in path/query
	logger.info(`Sending results to webhook: ${maskWebhookUrl(webhookUrl)}`);

	const response = await fetch(webhookUrl, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(payload),
	});

	if (!response.ok) {
		throw new Error(`Webhook request failed: ${response.status} ${response.statusText}`);
	}

	logger.info(`Webhook notification sent successfully (status: ${response.status})`);
}
