import jwt

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model

app = FastAPI()

JWT_SECRET = 'myjwtsecret'

class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)

    @classmethod
    async def get_user(cls, username):
        return cls.get(username=username)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


user_pydantic = pydantic_model_creator(User, name='User')
user_in_pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly=True)

oauth2_schema = OAuth2PasswordBearer(tokenUrl='token')


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user


@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)

    if not user:
       return {'error': 'Invalid credential'}

    user_obj = await user_pydantic.from_tortoise_orm(user)

    token = jwt.encode(user_obj.dict(), JWT_SECRET)

    return {'access_token': token, 'token_type': 'bearer'}


async def get_current_user(token: str = Depends(oauth2_schema)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get(id=payload.get('id'))
    except:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Invalid username or password')
    return await user_pydantic.from_tortoise_orm(user)


@app.post('/users', response_model=user_pydantic)
async def create(user: user_in_pydantic):
    user_obj = User(username=user.username, password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await user_pydantic.from_tortoise_orm(user_obj)


@app.get('/users/me', response_model=user_pydantic)
async def get_user(user: user_pydantic = Depends(get_current_user)):
    return user


register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True
)