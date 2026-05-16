import argparse
import asyncio
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.core.security import hash_password
from app.models.user import User


async def _create_admin(
    username: str,
    email: str,
    password: str,
) -> User:
    if len(password.encode("utf-8")) > 72:
        raise RuntimeError("Password too long for bcrypt (max 72 bytes)")

    async for session in get_db():  # type: AsyncSession
        result = await session.execute(
            select(User).where(User.is_admin.is_(True))
        )
        existing_admin: Optional[User] = result.scalar_one_or_none()
        if existing_admin:
            raise RuntimeError(
                f"Admin user already exists: id={existing_admin.id}, "
                f"username={existing_admin.username}, email={existing_admin.email}"
            )

        result = await session.execute(
            select(User).where(User.username == username)
        )
        if result.scalar_one_or_none():
            raise RuntimeError(f"User with username={username!r} already exists")

        result = await session.execute(
            select(User).where(User.email == email)
        )
        if result.scalar_one_or_none():
            raise RuntimeError(f"User with email={email!r} already exists")

        user = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            is_active=True,
            is_admin=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    raise RuntimeError("get_db() did not yield a session")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create initial admin user")
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)

    args = parser.parse_args()

    user = asyncio.run(_create_admin(args.username, args.email, args.password))
    print(
        f"Admin created: id={user.id}, username={user.username}, "
        f"email={user.email}, is_admin={user.is_admin}"
    )


if __name__ == "__main__":
    main()
