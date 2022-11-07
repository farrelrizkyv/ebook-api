<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    // public function register(Request $request)
    public function register(Request $request)
    {
        $field = $request->validate([
            'name' => 'required|string|max:100',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed|min:6'
        ]);

        $user = User::create([
            'name' => $field['name'],
            'email' => $field['email'],
            'password' => bcrypt($field['password'])
        ]);

        $token = $user->createToken('tokenku')->plainTextToken;

        $response = [
            'user' => $user,
            'tokern' => $token
        ];

        return response($response, 201);
    }
    public function login(request $request)
    {
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);
        $user = User::where('email', $fields['email'])->first();
        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response()->json([
                'message' => 'unauthorized'
            ], 401);
        }
        $token = $user->createToken('tokenku')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token
        ];
        return response()->json($response, 201);

    }
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return[
            'message' => 'Logged out'
        ];
    }
}
