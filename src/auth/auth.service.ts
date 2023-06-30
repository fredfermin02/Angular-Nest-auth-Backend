import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from "bcryptjs";

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from './entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';

import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterDto } from './dto/register-user.dto';
@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)  
    private userModel: Model<User>,
    private jwtService: JwtService,
  ){}
  

  async create(CreateUserDto: CreateUserDto):Promise<User> {
    
    try {
    const {password, ...userData} = CreateUserDto;
    const newUser = new this.userModel({
      password: bcryptjs.hashSync(password,10),
      ...userData
    });
  
    await newUser.save();
    const {password:_, ...user}=newUser.toJSON();
  
    return user;
      
    } catch (error) {
      if (error.code===11000) {
        throw new BadRequestException(`${CreateUserDto.email} alredy exists!`)
      }
        throw new InternalServerErrorException('Something terrible  happen!!! ')
    }  
    //1-Encriptar la contraseña

    //2-Guardar elusuario

    //3-Generar el JWT
  }

  async register(registerDto: RegisterDto): Promise<LoginResponse>{
    const user = await  this.create(registerDto);
  

    return {
    user:user,
    token: this.getJwt({id: user._id})
    }
}

  async login(loginDto: LoginDto):Promise<LoginResponse>{
    const {email, password} = loginDto;
    const user = await this.userModel.findOne({email});
    if (!user) {
      throw new UnauthorizedException('Credentials  not valid')
    }

    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Credentials  not valid passowird')      
    }

    const {password:_,...rest} = user.toJSON();

    return {
      user:rest,
      token: this.getJwt({id: user.id})
    }
    //console.log({loginDto})
  }

  findAll():Promise<User[]> {
    return this.userModel.find()
  }

  async findUserById(id: string){
    const user = await this.userModel.findById(id);
    const {password, ...rest} = user.toJSON();
    return rest;

  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwt(payload: JwtPayload){
    const token =this.jwtService.sign(payload);
    return token
  }
}
