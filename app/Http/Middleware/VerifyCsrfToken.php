<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;
use Illuminate\Support\Facades\Auth;

class VerifyCsrfToken extends Middleware
{
    /**
     * The URIs that should be excluded from CSRF verification.
     *
     * @var array<int, string>
     */
    protected $except = [
        'login',
        'logout',
        'keep-alive',
    ];

    /**
     * Token lama (session dibuat ulang / file session hilang) tidak boleh berujung 419.
     * Untuk user yang sudah login (termasuk hasil restore cookie persistent), request
     * dari origin yang sama tetap diterima; cross-site tetap ditolak.
     */
    protected function tokensMatch($request)
    {
        if (parent::tokensMatch($request)) {
            return true;
        }

        return Auth::check() && $this->isSameOrigin($request);
    }

    private function isSameOrigin($request): bool
    {
        $source = $request->headers->get('Origin');
        if (!$source || $source === 'null') {
            $source = $request->headers->get('Referer');
        }
        if (!$source) {
            return false;
        }

        $sourceHost = parse_url($source, PHP_URL_HOST);
        if (!$sourceHost) {
            return false;
        }

        $sourcePort = parse_url($source, PHP_URL_PORT);
        $sourceAuthority = strtolower($sourceHost . ($sourcePort ? ':' . $sourcePort : ''));

        return in_array($sourceAuthority, [
            strtolower($request->getHost()),
            strtolower($request->getHttpHost()),
        ], true);
    }
}
