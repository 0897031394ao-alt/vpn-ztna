import argparse
import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.models.user import User


async def _promote_to_admin(username: str) -> User:
    async for session in get_db():  # type: AsyncSession
        result = await session.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise RuntimeError(f"User not found: username={username!r}")

        if user.is_admin:
            print(
                f"User already admin: id={user.id}, username={user.username}, "
                f"is_admin={user.is_admin}, is_active={user.is_active}"
            )
            return user

        user.is_admin = True
        await session.commit()
        await session.refresh(user)
        print(
            f"Promoted to admin: id={user.id}, username={user.username}, "
            f"is_admin={user.is_admin}, is_active={user.is_active}"
        )
        return user

    raise RuntimeError("get_db() did not yield a session")


def main() -> None:
    parser = argparse.ArgumentParser(description="Promote user to admin")
    parser.add_argument("--username", required=True, help="Username to promote")

    args = parser.parse_args()
    asyncio.run(_promote_to_admin(args.username))


if __name__ == "__main__":
    main()

