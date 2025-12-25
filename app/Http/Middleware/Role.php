<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\JsonResponse;

class Role
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  mixed ...$roles
     * @return mixed
     */
    public function handle(Request $request, Closure $next, ...$roles)
    {
        $user = Auth::guard('sanctum')->user();

        if (!$user) {
            return new JsonResponse(['message' => 'Unauthorized'], 401);
        }

        // Map simple role names to boolean checks on the user model
        $roleChecks = [
            'admin' => (bool)($user->is_admin ?? false),
            'staff' => (bool)($user->is_staff ?? false),
        ];

        $allowed = false;
        foreach ($roles as $role) {
            if (isset($roleChecks[$role]) && $roleChecks[$role]) {
                $allowed = true;
                break;
            }
        }

        if (!$allowed) {
            return new JsonResponse(['message' => 'Forbidden'], 403);
        }

        return $next($request);
    }
}
