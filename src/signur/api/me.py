from fastapi import APIRouter

from signur.auth import CurrentUser
from signur.models import UserRole
from signur.schemas import MeView, UserView

router = APIRouter(tags=["identity"])


@router.get("/me", response_model=MeView)
def get_me(user: CurrentUser) -> MeView:
    profile = UserView.model_validate(user)
    has_access = user.role is not UserRole.NO_ACCESS
    return MeView(
        **profile.model_dump(),
        password_set=bool(user.password_hash),
        access_granted=has_access,
        access_message=(
            None
            if has_access
            else "Il tuo account è in attesa di autorizzazione. Contatta un amministratore."
        ),
    )
