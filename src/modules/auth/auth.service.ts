import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User } from './auth.schema';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async login(email: string, password: string, res: Response) {
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException({ message: 'Invalid credentials' });
    }

    const token = this.jwtService.sign({ userId: user._id });

    // Set JWT as HTTP-only cookie
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: false, // Set to `true` in production with HTTPS
      sameSite: 'lax', // Allow cross-origin cookies
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    console.log('Cookie Set:', token);

    return { message: 'Login successful', userId: user._id, token };
  }

  async register(email: string, password: string) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new this.userModel({ email, password: hashedPassword });
    await newUser.save();
    return { message: 'User created' };
  }
  async logout(res: Response) {
    res.clearCookie('jwt');
    return { message: 'Logout successful' };
  }
  async verify(token: string) {
    try {
      const payload = this.jwtService.verify(token);
      return { message: 'Token is valid', payload };
    } catch (error) {
      throw new UnauthorizedException({ message: 'Invalid token' });
    }
  }
}
