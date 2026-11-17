"""Har bir B vositasi faqat tasdiq navbatiga taklif yuboradi."""
from mcp.types import ToolAnnotations


def register_write_tools(mcp, run):
    note = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True)

    @mcp.tool(annotations=note)
    async def send_message(chat: int | str, text: str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('send_message', {'chat': chat, 'text': text})

    @mcp.tool(annotations=note)
    async def reply(chat: int | str, message_id: int, text: str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('reply', {'chat': chat, 'message_id': message_id, 'text': text})

    @mcp.tool(annotations=note)
    async def edit_message(chat: int | str, message_id: int, text: str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('edit_message', {'chat': chat, 'message_id': message_id, 'text': text})

    @mcp.tool(annotations=note)
    async def delete_messages(chat: int | str, message_ids: list[int], revoke: bool = True) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('delete_messages', {'chat': chat, 'message_ids': message_ids, 'revoke': revoke})

    @mcp.tool(annotations=note)
    async def forward_messages(chat: int | str, from_chat: int | str, message_ids: list[int]) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('forward_messages', {'chat': chat, 'from_chat': from_chat, 'message_ids': message_ids})

    @mcp.tool(annotations=note)
    async def send_file(chat: int | str, filename: str, caption: str = '') -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('send_file', {'chat': chat, 'filename': filename, 'caption': caption})

    @mcp.tool(annotations=note)
    async def react(chat: int | str, emoji: str, message_id: int) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('react', {'chat': chat, 'emoji': emoji, 'message_id': message_id})

    @mcp.tool(annotations=note)
    async def pin(chat: int | str, message_id: int, notify: bool = False) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('pin', {'chat': chat, 'message_id': message_id, 'notify': notify})

    @mcp.tool(annotations=note)
    async def unpin(chat: int | str, message_id: int) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('unpin', {'chat': chat, 'message_id': message_id})

    @mcp.tool(annotations=note)
    async def mark_read(chat: int | str, max_id: int) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('mark_read', {'chat': chat, 'max_id': max_id})

    @mcp.tool(annotations=note)
    async def join_chat(chat: int | str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('join_chat', {'chat': chat})

    @mcp.tool(annotations=note)
    async def leave_chat(chat: int | str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('leave_chat', {'chat': chat})

    @mcp.tool(annotations=note)
    async def create_group(title: str, users: list[int | str]) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('create_group', {'title': title, 'users': users})

    @mcp.tool(annotations=note)
    async def create_channel(title: str, about: str = '', megagroup: bool = False) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('create_channel', {'title': title, 'about': about, 'megagroup': megagroup})

    @mcp.tool(annotations=note)
    async def add_member(chat: int | str, user: int | str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('add_member', {'chat': chat, 'user': user})

    @mcp.tool(annotations=note)
    async def remove_member(chat: int | str, user: int | str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('remove_member', {'chat': chat, 'user': user})

    @mcp.tool(annotations=note)
    async def set_title(chat: int | str, title: str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('set_title', {'chat': chat, 'title': title})

    @mcp.tool(annotations=note)
    async def set_about(about: str, chat: int | str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('set_about', {'about': about, 'chat': chat})

    @mcp.tool(annotations=note)
    async def block(user: int | str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('block', {'user': user})

    @mcp.tool(annotations=note)
    async def unblock(user: int | str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('unblock', {'user': user})

    @mcp.tool(annotations=note)
    async def archive(chat: int | str, archived: bool = True) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('archive', {'chat': chat, 'archived': archived})

    @mcp.tool(annotations=note)
    async def mute(chat: int | str, muted: bool = True, hours: int = 24) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('mute', {'chat': chat, 'muted': muted, 'hours': hours})

    @mcp.tool(annotations=note)
    async def schedule_message(chat: int | str, text: str, when: str) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('schedule_message', {'chat': chat, 'text': text, 'when': when})

    @mcp.tool(annotations=note)
    async def send_poll(chat: int | str, options: list[str], question: str, anonymous: bool = True, multiple: bool = False) -> dict:
        """Faqat taklif: egasining alohida tasdig‘isiz bajarilmaydi."""
        return await run('send_poll', {'chat': chat, 'options': options, 'question': question, 'anonymous': anonymous, 'multiple': multiple})

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def action_status(action_id: str) -> dict:
        """Faqat o‘z amalingizning kutish yoki bajarilish holati."""
        return await run('action_status', {'action_id': action_id})
