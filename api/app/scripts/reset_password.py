import argparse
import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.core.security import hash_password
from app.models.user import User


async def _reset_password(username: str, new_password: str) -> User:
    if len(new_password.encode("utf-8")) > 72:
        raise RuntimeError("Password too long for bcrypt (max 72 bytes)")

    async for session in get_db():  # type: AsyncSession
        result = await session.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise RuntimeError(f"User not found: username={username!r}")

        user.hashed_password = hash_password(new_password)
        await session.commit()
        await session.refresh(user)
        return user

    raise RuntimeError("get_db() did not yield a session")


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset user password")
    parser.add_argument("--username", required=True, help="Username to update")
    parser.add_argument("--password", required=True, help="New plain-text password")

    args = parser.parse_args()

    user = asyncio.run(_reset_password(args.username, args.password))
    print(
        f"Password reset: id={user.id}, username={user.username}, "
        f"is_admin={user.is_admin}, is_active={user.is_active}"
    )


if __name__ == "__main__":
    main()

