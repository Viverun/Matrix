
import asyncio
from sqlalchemy import select
from core.database import async_session_maker
from models.user import User

async def check_users():
    async with async_session_maker() as session:
        try:
            result = await session.execute(select(User))
            users = result.scalars().all()
            print(f"Found {len(users)} users.")
            for user in users:
                print(f"User: {user.username}, Email: {user.email}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(check_users())
