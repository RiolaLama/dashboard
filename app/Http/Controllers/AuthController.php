<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        $data = $request->validated();
        $user = User::create([
            'first_name' => $data['firstName'],
            'last_name' => $data['lastName'],
            'email' => $data['email'],
            'password' => bcrypt($data['password'])
        ]);

        $token = $user->createToken('main')->plainTextToken;
        return response()->json([
            'user' => $user,
            'token' => $token,
        ], 201);
    }
    public function login(LoginRequest $request)
    {
        $credentials = $request->validated();
        $user = User::where('email', $request->email)->first();
        if (!Hash::check($request->password, $user->password)) {
            return response(
                [
                    'message' => 'Provided email or password is incorrect'
                ],
                422
            );
        }
        $token =  $user->createToken('main')->plainTextToken;
        return response(compact('user', 'token'));
    }
    public function logout(Request $request)
    {
        $user = $request->user()->tokens()->delete();
        // $user->currentAccessToken()->delete();
        return response([
            'message' => 'Logged out successfully'

        ]);
    }
}
